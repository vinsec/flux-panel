package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

type setElement struct {
	Key, Comment string
	Bytes        uint64
}
type setDefinition struct{ Name, Type, Options, Sentinel string }

var setDefinitions = []setDefinition{
	{bindingSet, "hash:ip,port", "family inet hashsize 4096 maxelem 1048576 comment skbinfo", "192.0.2.255,tcp:0"},
	{bindingSet + "_NEW", "hash:ip,port", "family inet hashsize 4096 maxelem 1048576 comment skbinfo", "192.0.2.255,tcp:0"},
	{allowSet, "hash:ip,mark", "family inet markmask 0xffffff00 hashsize 4096 maxelem 262144 comment", "192.0.2.255,0x0"},
	{allowSet + "_NEW", "hash:ip,mark", "family inet markmask 0xffffff00 hashsize 4096 maxelem 262144 comment", "192.0.2.255,0x0"},
	{upSet, "hash:ip,mark", "family inet markmask 0xffffff00 hashsize 4096 maxelem 262144 counters comment", "192.0.2.255,0x0"},
	{downSet, "hash:ip,mark", "family inet markmask 0xffffff00 hashsize 4096 maxelem 262144 counters comment", "192.0.2.255,0x0"},
}

func canonicalSetKey(key string) string {
	p := strings.Split(key, ",")
	if len(p) == 2 {
		if mark, e := strconv.ParseUint(p[1], 0, 32); e == nil {
			return fmt.Sprintf("%s,0x%x", p[0], mark&0xffffff00)
		}
	}
	return key
}
func parseSet(text string) map[string]setElement {
	out := map[string]setElement{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "add" {
			continue
		}
		v := setElement{Key: canonicalSetKey(f[2])}
		for i := 3; i+1 < len(f); i++ {
			switch f[i] {
			case "bytes":
				v.Bytes, _ = strconv.ParseUint(f[i+1], 10, 64)
			case "comment":
				v.Comment = strings.Trim(f[i+1], "\"")
			}
		}
		out[v.Key] = v
	}
	return out
}
func (k *IPTables) readSet(name string) (string, error) { return k.run("ipset", "", "save", name) }
func (k *IPTables) initializeSets() error {
	text, e := k.run("ipset", "", "list", "-name")
	if e != nil {
		return e
	}
	existing := map[string]bool{}
	for _, n := range strings.Fields(text) {
		existing[n] = true
	}
	for _, d := range setDefinitions {
		if existing[d.Name] {
			saved, e := k.readSet(d.Name)
			if e != nil {
				return e
			}
			header := strings.Split(saved, "\n")[0]
			if !strings.HasPrefix(header, "create "+d.Name+" "+d.Type+" ") || !strings.Contains(saved, "comment \""+owner+"\"") && !strings.Contains(saved, "comment "+owner) {
				return fmt.Errorf("ipset %s exists without v2 ownership/type", d.Name)
			}
			for _, required := range []string{"counters", "skbinfo"} {
				if strings.Contains(d.Options, required) && !strings.Contains(header, required) {
					return fmt.Errorf("ipset %s lacks %s", d.Name, required)
				}
			}
			if strings.Contains(d.Type, "mark") && !strings.Contains(header, "markmask 0xffffff00") {
				return fmt.Errorf("ipset %s has incompatible mark mask", d.Name)
			}
		} else {
			args := append([]string{"create", d.Name, d.Type}, strings.Fields(d.Options)...)
			if _, e = k.run("ipset", "", args...); e != nil {
				return e
			}
			if _, e = k.run("ipset", "", "add", d.Name, d.Sentinel, "comment", owner); e != nil {
				return e
			}
		}
	}
	return nil
}
func (k *IPTables) setCounters() (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, name := range []string{upSet, downSet} {
		text, e := k.readSet(name)
		if e != nil {
			return nil, e
		}
		for _, v := range parseSet(text) {
			p := strings.Split(v.Comment, ":")
			if len(p) != 4 || p[0] != "flux" || p[1] != "v2" {
				continue
			}
			key := "flux:v2:" + p[2] + ":all:" + p[3]
			out[key] += v.Bytes
		}
	}
	return out, nil
}
func localIPv4s() ([]string, error) {
	as, e := net.InterfaceAddrs()
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, a := range as {
		ip, _, e := net.ParseCIDR(a.String())
		if e == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			seen[ip.String()] = true
		}
	}
	out := []string{}
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}
func targetKey(s Spec) string { return fmt.Sprintf("%s,0x%x", s.TargetIP, flowMark(s)) }
func (k *IPTables) plans(plan []Spec) (map[string]string, map[string]string, error) {
	ips, e := localIPv4s()
	if e != nil {
		return nil, nil, e
	}
	bindings, active := map[string]string{}, map[string]string{}
	for _, s := range plan {
		if s.Deleted {
			continue
		}
		listen := []string{s.ListenIP}
		if s.ListenIP == "0.0.0.0" {
			listen = ips
		}
		for _, ip := range listen {
			for _, proto := range []string{"tcp", "udp"} {
				key := fmt.Sprintf("%s,%s:%d", ip, proto, s.ListenPort)
				bindings[key] = fmt.Sprintf("skbmark 0x%x/%s comment flux:v2:%s:binding", flowMark(s), markMask, s.ID)
			}
		}
		if s.Active() {
			active[targetKey(s)] = "comment flux:v2:" + s.ID + ":active"
		}
	}
	return bindings, active, nil
}
func (k *IPTables) prepareCounters(plan []Spec) error {
	var restore strings.Builder
	for _, pair := range []struct{ Name, Direction string }{{upSet, "up"}, {downSet, "down"}} {
		saved, e := k.readSet(pair.Name)
		if e != nil {
			return e
		}
		existing := parseSet(saved)
		for _, s := range plan {
			if s.Deleted {
				continue
			}
			key := targetKey(s)
			comment := "flux:v2:" + s.ID + ":" + pair.Direction
			if old, ok := existing[key]; ok {
				if old.Comment != comment {
					return fmt.Errorf("persistent mark/counter owner mismatch for %s", key)
				}
				continue
			}
			fmt.Fprintf(&restore, "add %s %s comment %s\n", pair.Name, key, comment)
			existing[key] = setElement{Comment: comment}
		}
	}
	if restore.Len() > 0 {
		_, e := k.run("ipset", restore.String(), "restore")
		return e
	}
	return nil
}
func (k *IPTables) stageSet(name string, entries map[string]string) error {
	var d setDefinition
	for _, v := range setDefinitions {
		if v.Name == name+"_NEW" {
			d = v
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush %s\nadd %s %s comment %s\n", d.Name, d.Name, d.Sentinel, owner)
	names := []string{}
	for key := range entries {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		fmt.Fprintf(&b, "add %s %s %s\n", d.Name, key, entries[key])
	}
	_, e := k.run("ipset", b.String(), "restore")
	return e
}
func (k *IPTables) policy(active map[string]string) error {
	text, e := k.readSet(allowSet)
	if e != nil {
		return e
	}
	old := parseSet(text)
	delete(old, "192.0.2.255,0x0")
	changes := []struct {
		Add bool
		Key string
	}{}
	for key := range old {
		if _, ok := active[key]; !ok {
			changes = append(changes, struct {
				Add bool
				Key string
			}{false, key})
		}
	}
	for key := range active {
		if _, ok := old[key]; !ok {
			changes = append(changes, struct {
				Add bool
				Key string
			}{true, key})
		}
	}
	if len(changes) == 0 {
		return nil
	}
	if len(changes) == 1 {
		c := changes[0]
		args := []string{"-exist", "del", allowSet, c.Key}
		if c.Add {
			args = []string{"-exist", "add", allowSet, c.Key}
			args = append(args, strings.Fields(active[c.Key])...)
		}
		_, e = k.run("ipset", "", args...)
		return e
	}
	if e = k.stageSet(allowSet, active); e != nil {
		return e
	}
	_, e = k.run("ipset", "", "swap", allowSet+"_NEW", allowSet)
	return e
}
func shapeDigest(tables map[string]string, bindings map[string]string) string {
	keys := []string{}
	for key, value := range bindings {
		keys = append(keys, key+"="+value)
	}
	sort.Strings(keys)
	data := tables["mangle"] + tables["filter"] + tables["nat"] + strings.Join(keys, "\n")
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
func decodePlan(tables map[string]string) ([]Spec, error) {
	var p []Spec
	e := json.Unmarshal([]byte(tables["ipset_plan"]), &p)
	return p, e
}
