package engine

import "testing"

func TestReturnPathEvidenceDoesNotOverstateReverseRoute(t *testing.T) {
	cases := []struct {
		rpf   any
		route map[string]any
		want  string
	}{
		{nil, map[string]any{"available": true, "dev": "r0"}, "unknown"},
		{0, nil, "disabled"},
		{1, map[string]any{"available": false}, "unreachable-risk"},
		{1, map[string]any{"available": true, "dev": "r1"}, "strict-interface-mismatch-risk"},
		{2, map[string]any{"available": true, "dev": "r1"}, "no-obvious-destination-route-conflict"},
	}
	for _, c := range cases {
		if got := reversePathRisk(c.rpf, c.route, "r0"); got != c.want {
			t.Fatal(got, c.want)
		}
	}
	if effectiveSysctl(1, 2) != 2 || effectiveSysctl(nil, 2) != nil {
		t.Fatal("effective sysctl must preserve unknown or use the larger kernel value")
	}
	for _, ip := range []string{"example.test", "0.0.0.0", "::", "224.0.0.1", "fe80::1%eth0", "127.0.0.1;id"} {
		if (ReturnPathQuery{ClientIP: ip}).validate() == nil {
			t.Fatal("unsafe client accepted", ip)
		}
	}
}
func TestPinnedProgramRecordRequiresCommittedBootAndIdentity(t *testing.T) {
	info := localProgramInfo{Type: 3, ID: 19, Tag: [8]byte{1}}
	record := preparedProgram{Version: 1, Phase: "ready", ObjectSHA256: localObjectKey(), BootID: "boot", ID: 19, Tag: "0100000000000000"}
	if e := checkPreparedRecord(record, info, "boot", true); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*preparedProgram){func(r *preparedProgram) { r.Phase = "prepared" }, func(r *preparedProgram) { r.BootID = "old" }, func(r *preparedProgram) { r.ID++ }, func(r *preparedProgram) { r.ObjectSHA256 = "other" }, func(r *preparedProgram) { r.Tag = "other" }} {
		c := record
		change(&c)
		if checkPreparedRecord(c, info, "boot", true) == nil {
			t.Fatal("uncommitted/stale/unowned pin accepted", c)
		}
	}
	record.Phase = "prepared"
	if checkPreparedRecord(record, info, "boot", false) != nil {
		t.Fatal("preparer cannot resume its owned interrupted commit")
	}
}
