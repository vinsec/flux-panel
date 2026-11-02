package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// nft 1.0.6 omits table comments from JSON even though the kernel stores them.
// Recover only the canonical table-level comment, never a nested object comment.
func nftTableTextComment(text, family, name string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != fmt.Sprintf("table %s %s {", family, name) {
		return "", false
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "comment ") {
			return "", false
		}
		value, e := strconv.Unquote(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "comment "), ";")))
		return value, e == nil
	}
	return "", false
}
func nftJSONTableComments(text string, load func(string, string) (string, error)) (string, error) {
	var d nativeDocument
	if json.Unmarshal([]byte(text), &d) != nil {
		return text, nil
	}
	changed := false
	for _, entry := range d.NFT {
		raw := entry["table"]
		if raw == nil {
			continue
		}
		var t map[string]any
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		family, _ := t["family"].(string)
		name, _ := t["name"].(string)
		if family != "inet" || (name != nativeTable && name != protocolTable && name != "FP_GOST_WORKER") {
			continue
		}
		if _, present := t["comment"]; present {
			continue
		}
		saved, e := load(family, name)
		if e != nil {
			return "", e
		}
		comment, ok := nftTableTextComment(saved, family, name)
		if !ok {
			continue
		}
		t["comment"] = comment
		entry["table"], _ = json.Marshal(t)
		changed = true
	}
	if !changed {
		return text, nil
	}
	out, e := json.Marshal(d)
	return string(out), e
}
