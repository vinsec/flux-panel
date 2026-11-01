package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type PreflightResult struct {
	Kernel     string   `json:"kernel"`
	Backend    string   `json:"backend"`
	Forwarding bool     `json:"forwarding"`
	MarkMask   string   `json:"markMask"`
	Probes     []string `json:"probes"`
}

func (k *NativeKernel) Preflight() (PreflightResult, error) { return k.Native.preflight() }

// Index ownership in one pass. Re-scanning a large ruleset for every rule
// makes a warm 10k-rule restart quadratic even though packet dispatch is O(1).
var reservedMark = regexp.MustCompile(`(?i)0xf[12][0-9a-f]{6}`)

const owner = "flux-owner:v3"
const previousOwner = "flux-owner:v2"
const gateComment = "flux-transaction:v3"
const advancedGate = "flux-advanced-transaction:v4"

func markOwners(saved string) map[string]bool {
	declared := map[string]bool{}
	for _, m := range declaration.FindAllStringSubmatch(saved, -1) {
		declared[m[1]] = true
	}
	owners := map[string]bool{}
	for _, line := range strings.Split(saved, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "[") && strings.HasSuffix(f[0], "]") {
			f = f[1:]
		}
		if len(f) != 8 || f[0] != "-A" || !declared[f[1]] || f[2] != "-m" || f[3] != "comment" || f[4] != "--comment" || f[6] != "-j" || f[7] != "RETURN" {
			continue
		}
		name, marker := f[1], strings.Trim(f[5], "\"")
		if ownedNames.MatchString(name) && (marker == owner || marker == previousOwner || marker == "flux-owner:v1") {
			owners[name] = true
		}
		if (strings.HasPrefix(name, "FP4_") || strings.HasPrefix(name, "FP6_")) && marker == advancedOwner {
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
	// A protocol table is trusted only by its exact table-level owner marker.
	for _, obj := range document.NFT {
		if raw := obj["table"]; raw != nil {
			var t struct{ Family, Name string }
			_ = json.Unmarshal(raw, &t)
			if t.Family == "inet" && t.Name == protocolTable {
				if !protocolOwned(text) {
					return fmt.Errorf("foreign protocol table")
				}
				owners["inet:"+protocolTable] = map[string]bool{"forward": true, "input": true, "output": true}
			}
		}
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
