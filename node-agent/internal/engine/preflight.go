package engine

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type PreflightResult struct {
	Kernel     string   `json:"kernel"`
	Backend    string   `json:"backend"`
	IPSet      string   `json:"ipset"`
	Forwarding bool     `json:"forwarding"`
	MarkMask   string   `json:"markMask"`
	Probes     []string `json:"probes"`
}

func (k *IPTables) Preflight() (PreflightResult, error) {
	result := PreflightResult{MarkMask: markMask}
	var e error
	if result.Kernel, e = k.run("uname", "", "-r"); e != nil {
		return result, e
	}
	if result.Backend, e = k.run(k.Binary, "", "--version"); e != nil {
		return result, e
	}
	if result.IPSet, e = k.run("ipset", "", "--version"); e != nil {
		return result, e
	}
	text, e := k.run("cat", "", "/proc/sys/net/ipv4/ip_forward")
	if e != nil {
		return result, e
	}
	result.Forwarding = text == "1"
	if !result.Forwarding {
		return result, fmt.Errorf("IPv4 forwarding must already be enabled in this network namespace")
	}
	ownedTables := map[string]map[string]bool{}
	for _, table := range []string{"filter", "mangle", "nat"} {
		saved, e := k.run(k.Binary+"-save", "", "-t", table)
		if e != nil {
			return result, e
		}
		ownedTables[table] = markOwners(saved)
		ownedTables["ip:"+table] = ownedTables[table]
		if e = validateExternalMarks(saved); e != nil {
			return result, e
		}
	}
	if k.P1 != nil {
		binary := strings.Replace(k.Binary, "iptables", "ip6tables", 1)
		for _, table := range []string{"filter", "mangle", "nat"} {
			if saved, err := k.run(binary+"-save", "", "-t", table); err == nil {
				ownedTables["ip6:"+table] = markOwners(saved)
				if err = validateExternalMarks(saved); err != nil {
					return result, err
				}
			}
		}
	}
	other := "iptables-legacy"
	if strings.Contains(result.Backend, "legacy") {
		other = "iptables-nft"
	}
	if _, e := exec.LookPath(other + "-save"); e == nil {
		if saved, e := k.run(other+"-save", ""); e == nil && strings.Contains(saved, "flux-owner:") {
			return result, fmt.Errorf("another iptables backend already owns Flux rules")
		}
	}
	if _, e = exec.LookPath("nft"); e != nil {
		return result, fmt.Errorf("nft is required to audit native flow-offload and mark conflicts")
	}
	native, e := k.run("nft", "", "-j", "list", "ruleset")
	if e != nil {
		return result, e
	}
	if e = validateNativeRules(native, ownedTables); e != nil {
		return result, e
	}
	prefix := "FPCHK_" + identity()[:12]
	created := []string{}
	defer func() {
		for i := len(created) - 1; i >= 0; i-- {
			_, _ = k.run("ipset", "", "destroy", created[i])
		}
	}()
	create := func(name, typ string, args ...string) error {
		all := append([]string{"create", name, typ}, args...)
		_, e := k.run("ipset", "", all...)
		if e == nil {
			created = append(created, name)
		}
		return e
	}
	b, c, swap := prefix+"b", prefix+"c", prefix+"s"
	if e = create(b, "hash:ip,port", "family", "inet", "skbinfo", "comment"); e != nil {
		return result, e
	}
	if e = create(swap, "hash:ip,port", "family", "inet", "skbinfo", "comment"); e != nil {
		return result, e
	}
	if e = create(c, "hash:ip,mark", "family", "inet", "markmask", markMask, "counters", "timeout", "60", "comment"); e != nil {
		return result, e
	}
	if _, e = k.run("ipset", "", "add", b, "192.0.2.1,tcp:9", "skbmark", "0xf1000100/"+markMask); e != nil {
		return result, e
	}
	if _, e = k.run("ipset", "", "add", c, "192.0.2.1,0xf1000100", "bytes", fmt.Sprint(creditCeiling-100), "timeout", "1"); e != nil {
		return result, e
	}
	if _, e = k.run("ipset", "", "-exist", "add", c, "192.0.2.1,0xf1000100", "timeout", "1", "comment", "ttl-renewal-probe"); e != nil {
		return result, e
	}
	renewed, e := k.readSet(c)
	if e != nil {
		return result, e
	}
	if parseSet(renewed)["192.0.2.1,0xf1000100"].Bytes != creditCeiling-100 {
		return result, fmt.Errorf("kernel cannot safely renew timeout without resetting counters")
	}
	plan := fmt.Sprintf("*mangle\n:%s - [0:0]\n-A %s -m set --match-set %s dst,dst -j SET --map-set %s dst,dst --map-mark\nCOMMIT\n", prefix, prefix, b, b)
	if _, e = k.run(k.Binary+"-restore", plan, "--test", "--noflush", "--wait", "2"); e != nil {
		return result, e
	}
	plan = fmt.Sprintf("*filter\n:%s - [0:0]\n-A %s -m conntrack --ctstate RELATED -p icmp -j RETURN\n-A %s -m set --match-set %s dst,dst --bytes-lt %d -j RETURN\nCOMMIT\n", prefix, prefix, prefix, c, creditCeiling)
	if _, e = k.run(k.Binary+"-restore", plan, "--test", "--noflush", "--wait", "2"); e != nil {
		return result, e
	}
	if _, e = k.run("ipset", "", "swap", b, swap); e != nil {
		return result, e
	}
	result.Probes = []string{"hash:ip,port skbinfo/map-mark", "hash:ip,mark counters/timeout/bytes-lt", "RELATED ICMP", "counter-preserving TTL renewal", "atomic ipset swap", "backend exclusivity", "native nft flow-offload/mark audit"}
	return result, nil
}
func markOwners(saved string) map[string]bool {
	owners := map[string]bool{}
	for _, m := range declaration.FindAllStringSubmatch(saved, -1) {
		name := m[1]
		if ownedNames.MatchString(name) && (knownOwnedChain(saved, name) || strings.Contains(saved, "-A "+name+" -m comment --comment flux-owner:v1 -j RETURN") || strings.Contains(saved, "-A "+name+" -m comment --comment \"flux-owner:v1\" -j RETURN")) {
			owners[name] = true
		}
		if (strings.HasPrefix(name, "FP4_") || strings.HasPrefix(name, "FP6_")) && advancedOwnedChain(saved, name) {
			owners[name] = true
		}
	}
	return owners
}
func validateExternalMarks(saved string) error { return validateMarkBits(saved, 0xffffff00) }
func validateMarkBits(saved string, reserved uint64) error {
	owners := markOwners(saved)
	for _, line := range strings.Split(saved, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "-A" || owners[f[1]] {
			continue
		}
		if (strings.Contains(line, gateComment) || strings.Contains(line, advancedGate)) && strings.Contains(line, "-j DROP") {
			continue
		}
		if reservedMark.MatchString(line) {
			return fmt.Errorf("reserved connmark namespace is already used outside owned chains")
		}
		for i, v := range f {
			if v == "--set-mark" || v == "--set-xmark" || v == "--and-mark" || v == "--or-mark" || v == "--xor-mark" {
				if i+1 >= len(f) {
					return fmt.Errorf("invalid external mark rule")
				}
				parts := strings.Split(f[i+1], "/")
				mask := uint64(0xffffffff)
				if len(parts) == 2 {
					var e error
					mask, e = strconv.ParseUint(parts[1], 0, 32)
					if e != nil {
						return e
					}
				}
				if v == "--or-mark" || v == "--xor-mark" {
					mask, _ = strconv.ParseUint(parts[0], 0, 32)
				}
				if v == "--and-mark" {
					value, _ := strconv.ParseUint(parts[0], 0, 32)
					mask = ^value
				}
				if v == "--set-mark" || v == "--set-xmark" {
					value, e := strconv.ParseUint(parts[0], 0, 32)
					if e != nil {
						return e
					}
					mask |= value
				}
				if mask&reserved != 0 {
					return fmt.Errorf("external mark writer overlaps Flux token bits")
				}
			}
			if v == "--save-mark" || v == "--restore-mark" {
				nfmask, ctmask := uint64(0xffffffff), uint64(0xffffffff)
				for j, x := range f {
					if (x == "--nfmask" || x == "--ctmask") && j+1 < len(f) {
						n, e := strconv.ParseUint(f[j+1], 0, 32)
						if e != nil {
							return e
						}
						if x == "--nfmask" {
							nfmask = n
						} else {
							ctmask = n
						}
					}
				}
				if (nfmask|ctmask)&reserved != 0 {
					return fmt.Errorf("external CONNMARK writer overlaps Flux token bits")
				}
			}

		}
	}
	return nil
}
func validateNativeRules(text string, owners map[string]map[string]bool) error {
	var document struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	if e := json.Unmarshal([]byte(text), &document); e != nil {
		return e
	}
	for _, obj := range document.NFT {
		raw, ok := obj["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Chain  string                       `json:"chain"`
			Family string                       `json:"family"`
			Table  string                       `json:"table"`
			Expr   []map[string]json.RawMessage `json:"expr"`
		}
		if e := json.Unmarshal(raw, &rule); e != nil {
			return e
		}
		for _, expression := range rule.Expr {
			if _, ok := expression["flow"]; ok {
				return fmt.Errorf("native flow offload can bypass pause and quota enforcement")
			}
			if v, ok := expression["mangle"]; ok && !(rule.Family == "ip" && owners[rule.Table][rule.Chain] || owners[rule.Family+":"+rule.Table][rule.Chain]) {
				var m struct {
					Key json.RawMessage `json:"key"`
				}
				_ = json.Unmarshal(v, &m)
				if strings.Contains(string(m.Key), "\"mark\"") {
					return fmt.Errorf("native nft mark writer overlaps Flux ownership; isolate or allocate compatible bits")
				}
			}
		}
	}
	return nil
}
