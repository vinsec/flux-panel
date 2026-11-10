package engine

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type preflightKernel struct {
	guardedKernel
	reject bool
}

func (k *preflightKernel) CheckApply(map[string]string) error {
	if k.reject {
		return errors.New("nft parser rejected configuration")
	}
	return nil
}

func TestRejectedPreflightDoesNotFenceOrAlterLedger(t *testing.T) {
	k := &preflightKernel{guardedKernel: guardedKernel{memoryKernel: memoryKernel{counters: map[string]uint64{}}}}
	m, err := New(filepath.Join(t.TempDir(), "state.json"), k)
	if err != nil {
		t.Fatal(err)
	}
	s := valid()
	if err = m.Apply(s); err != nil {
		t.Fatal(err)
	}
	before := cloneState(m.state)
	checkpoint, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	calls := k.calls
	k.reject = true
	s.Revision++
	s.TargetPort++
	if err = m.Apply(s); err == nil || !strings.Contains(err.Error(), "configuration preflight") {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(m.Path)
	if k.gated || m.blocked || k.calls != calls || !reflect.DeepEqual(m.state, before) || string(checkpoint) != string(after) {
		t.Fatal("preflight failure changed live forwarding or accounting")
	}
	if _, err = os.Stat(m.Path + ".journal"); !os.IsNotExist(err) {
		t.Fatal("preflight created a recovery journal", err)
	}
	k.reject = false
	if err = m.Apply(s); err != nil {
		t.Fatal("valid retry failed", err)
	}
}
