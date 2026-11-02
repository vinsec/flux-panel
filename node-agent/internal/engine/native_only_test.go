package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetiredBackupCannotOverwriteANativeLedger(t *testing.T) {
	dir := t.TempDir()
	state := []byte(`{"kernelBackend":"iptables","epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":19,"rules":{}}`)
	if e := os.WriteFile(filepath.Join(dir, "state.json"), state, 0600); e != nil {
		t.Fatal(e)
	}
	m := MaintenanceManifest{Version: 1, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Files: map[string]string{"state.json": digestBytes(state)}}
	b, _ := json.Marshal(m)
	if e := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := verifyBackup(dir); e == nil || !strings.Contains(e.Error(), "retired") {
		t.Fatal(e)
	}
}

func TestRetiredCheckpointRejectedBeforeAnyKernelAccess(t *testing.T) {
	for _, backend := range []string{"", "iptables", "unknown"} {
		p := filepath.Join(t.TempDir(), "state.json")
		before := []byte(`{"kernelBackend":"` + backend + `","epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":19,"totals":{"1_1_0":{"up":123}},"rules":{}}`)
		if e := os.WriteFile(p, before, 0600); e != nil {
			t.Fatal(e)
		}
		// Uninitialized concrete kernel intentionally panics if touched.
		if _, e := New(p, &NativeKernel{}); e == nil || !strings.Contains(e.Error(), "retired") {
			t.Fatal(e)
		}
		after, _ := os.ReadFile(p)
		if string(after) != string(before) {
			t.Fatal("retired ledger changed")
		}
	}
}

func TestNativePlanHasNoXtablesProgram(t *testing.T) {
	p := Render(map[string]Spec{"1_2_3": valid()}, nil)
	if len(p) != 1 || p["kernel_plan"] == "" {
		t.Fatal(p)
	}
	specs, e := decodePlan(p)
	if e != nil || len(specs) != 1 || specs[0].Token == 0 {
		t.Fatal(specs, e)
	}
	// Actual immutable nft graph generation is covered by the scale/compiler tests.
}
