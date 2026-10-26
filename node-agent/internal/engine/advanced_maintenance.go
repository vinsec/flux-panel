package engine

import (
	"fmt"
	"os"
	"strings"
)

func (a *AdvancedKernel) backupExtras() (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		p := a.plane(family)
		for _, table := range []string{"filter", "nat", "mangle"} {
			text, e := a.parent.run(p.binary+"-save", "", "-c", "-t", table)
			if e != nil {
				return nil, e
			}
			files[family+"-"+table+".rules"] = []byte(text)
		}
	}
	if data, e := os.ReadFile(a.StatePath + ".aux.json"); e == nil {
		files["aux-state.json"] = data
	}
	if text, e := a.parent.run("nft", "", "-j", "list", "table", "inet", quotaTable); e == nil {
		files["shared-quota.json"] = []byte(text)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		flag := "-4"
		if family == "ipv6" {
			flag = "-6"
		}
		if text, e := a.parent.run("ip", "", "-j", flag, "rule", "show"); e == nil {
			files[family+"-policy-rules.json"] = []byte(text)
		}
	}
	if text, e := a.parent.run("tc", "", "-s", "class", "show", "dev", shapingDevice); e == nil {
		files["shaping-classes.txt"] = []byte(text)
	}
	return files, nil
}
func (a *AdvancedKernel) cleanup() error {
	if _, e := os.Stat(a.StatePath + ".aux.json"); e == nil {
		aux, e := a.auxiliary()
		if e != nil {
			return e
		}
		if e = aux.apply(map[string]Spec{}); e != nil {
			return e
		}
		if e = os.Remove(a.StatePath + ".aux.json"); e != nil {
			return e
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !a.ready[family] {
			continue
		}
		p := a.plane(family)
		if _, e := a.parent.run("conntrack", "", "-D", "-f", family, "--mark", advancedMark); e != nil && !strings.Contains(e.Error(), "0 flow entries") {
			return e
		}
		for _, table := range []string{"mangle", "nat", "filter"} {
			saved, e := a.parent.run(p.binary+"-save", "", "-t", table)
			if e != nil {
				return e
			}
			owned := map[string]bool{}
			owners := markOwners(saved)
			for _, m := range declaration.FindAllStringSubmatch(saved, -1) {
				name := m[1]
				if strings.HasPrefix(name, p.prefix+"_") {
					if !owners[name] {
						return fmt.Errorf("advanced cleanup found a foreign chain")
					}
					owned[name] = true
				}
			}
			var declarations, deleteHooks, deleteChains strings.Builder
			for _, name := range sortedNames(owned) {
				fmt.Fprintf(&declarations, ":%s - [0:0]\n", name)
				fmt.Fprintf(&deleteChains, "-X %s\n", name)
			}
			for _, line := range strings.Split(saved, "\n") {
				f := strings.Fields(line)
				if len(f) < 3 || f[0] != "-A" || owned[f[1]] {
					continue
				}
				references := false
				for _, part := range f {
					if owned[strings.Trim(part, "\"")] {
						references = true
					}
				}
				if references {
					if !strings.Contains(line, "flux-advanced-hook:v4") {
						return fmt.Errorf("foreign rule references advanced chains")
					}
					deleteHooks.WriteString(strings.Replace(line, "-A ", "-D ", 1) + "\n")
				}
			}
			if len(owned) > 0 {
				input := "*" + table + "\n" + declarations.String() + deleteHooks.String() + deleteChains.String() + "COMMIT\n"
				if _, e = a.parent.run(p.binary+"-restore", input, "--test", "--noflush", "--wait", "2"); e != nil {
					return e
				}
				if _, e = a.parent.run(p.binary+"-restore", input, "--noflush", "--wait", "2"); e != nil {
					return e
				}
			}
		}
		for _, suffix := range []string{"BIND", "BNEW", "ALLOW", "ANEW", "UP", "DOWN", "ROUTES", "RNEW", "OBIND", "ONEW", "NOSNAT", "SNEW", "LORIG", "LONEW", "LTARG", "LTNEW"} {
			name := p.set(suffix)
			saved, e := a.parent.readSet(name)
			if e != nil {
				continue
			}
			if !strings.Contains(saved, advancedOwner) {
				return fmt.Errorf("advanced cleanup refuses foreign set")
			}
			if _, e = a.parent.run("ipset", "", "destroy", name); e != nil {
				return e
			}
		}
	}
	if saved, e := a.parent.run("nft", "", "-j", "list", "table", "inet", quotaTable); e == nil {
		if !strings.Contains(saved, advancedOwner) {
			return fmt.Errorf("shared quota table is foreign")
		}
		if _, e = a.parent.run("nft", "", "delete", "table", "inet", quotaTable); e != nil {
			return e
		}
	}
	a.quota = &SharedQuota{parent: a.parent}
	if e := a.gate(nil, false, true); e != nil && !strings.Contains(e.Error(), "No such") {
		return e
	}
	a.ready = map[string]bool{}
	a.shape = map[string]string{}
	a.control = map[string]string{}
	a.bindings = map[string]string{}
	a.last = map[string]Spec{}
	a.aux = nil
	a.quota = &SharedQuota{parent: a.parent}
	return nil
}
