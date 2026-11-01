package engine

import (
	"fmt"
	"os"
	"strings"
)

func (a *AdvancedKernel) backupExtras() (map[string][]byte, error) {
	files := map[string][]byte{}
	// Maintenance runs before Initialize, so discover the table directly rather
	// than relying on an in-process classifier pointer.
	tables, e := a.parent.run("nft", "", "-j", "list", "tables")
	if e != nil {
		return nil, e
	}
	if strings.Contains(tables, `"`+protocolTable+`"`) {
		owned, e := a.parent.run("nft", "", "-j", "list", "table", "inet", protocolTable)
		if e != nil {
			return nil, e
		}
		if !protocolOwned(owned) {
			return nil, fmt.Errorf("foreign protocol table")
		}
		saved, e := a.parent.run("nft", "", "list", "table", "inet", protocolTable)
		if e != nil {
			return nil, e
		}
		files["protocol-filter.rules"] = []byte(saved)
	}

	if a.parent.Native != nil {
		text, e := a.parent.Native.run("", "list", "table", "inet", nativeTable)
		if e != nil {
			return nil, e
		}
		files["native-nft.rules"] = []byte(text)
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
