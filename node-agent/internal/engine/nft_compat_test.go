package engine

import (
	"encoding/json"
	"testing"
)

func TestOldNFTJSONRecoversExactTableComment(t *testing.T) {
	raw := `{"nftables":[{"table":{"family":"inet","name":"FP_GOST_WORKER","handle":1}}]}`
	saved, e := nftJSONTableComments(raw, func(f, n string) (string, error) {
		return "table inet FP_GOST_WORKER {\n comment \"flux-managed-gost:v1\"\n chain input {\n }\n}", nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var d nativeDocument
	if e = json.Unmarshal([]byte(saved), &d); e != nil {
		t.Fatal(e)
	}
	var row struct{ Comment string }
	json.Unmarshal(d.NFT[0]["table"], &row)
	if row.Comment != "flux-managed-gost:v1" {
		t.Fatal(saved)
	}
	explicit := `{"nftables":[{"table":{"family":"inet","name":"FP_GOST_WORKER","comment":"foreign"}}]}`
	got, e := nftJSONTableComments(explicit, func(string, string) (string, error) { t.Fatal("must not override explicit ownership"); return "", nil })
	if e != nil || got != explicit {
		t.Fatal(got, e)
	}
}
func TestNFTCommentCannotBeSpoofedByNestedObject(t *testing.T) {
	for _, text := range []string{"table inet FP_GOST_WORKER {\n chain input {\n comment \"flux-managed-gost:v1\"\n}\n}", "table inet OTHER {\n comment \"flux-managed-gost:v1\"\n}", "table inet FP_GOST_WORKER {\n comment \"foreign:flux-managed-gost:v1\"\n}"} {
		value, ok := nftTableTextComment(text, "inet", "FP_GOST_WORKER")
		if ok && value == "flux-managed-gost:v1" {
			t.Fatal("spoof accepted", text)
		}
	}
}
