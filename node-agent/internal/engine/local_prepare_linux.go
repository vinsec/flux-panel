//go:build linux

package engine

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// PrepareLocalShaping is an explicit short-lived administrative command. It
// never reads a panel secret, creates forwarding rules, or changes MTU/sysctl.
// Stock tc/libbpf may enumerate module BTFs here; the daemon only uses OBJ_GET.
func PrepareLocalShaping() (result map[string]any, failure error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("local shaping preparation requires root")
	}
	if e := privateLocalDirectory(localPrepareDirectory, true); e != nil {
		return nil, e
	}
	lockPath := filepath.Join(localPrepareDirectory, "prepare.lock")
	fd, e := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return nil, fmt.Errorf("local BPF preparation already running: %w", e)
	}
	if e = privateLocalDirectory(localPinDirectory, true); e != nil {
		return nil, e
	}
	if e = localBPFFilesystem(); e != nil {
		return nil, e
	}
	for _, name := range []string{"tc", "ip", "xdp"} {
		if e = os.MkdirAll("/sys/fs/bpf/"+name+"/globals", 0700); e != nil {
			return nil, e
		}
	}
	boot, e := localBootID()
	if e != nil {
		return nil, e
	}
	existing, recordError := readPreparedRecord()
	if info, e := inspectLocalProgramPin(localProgramPin()); e == nil {
		if recordError != nil {
			return nil, fmt.Errorf("unowned local BPF pin: %w", recordError)
		}
		if e = checkPreparedRecord(existing, info, boot, false); e != nil {
			return nil, e
		}
		existing.Phase = "ready"
		if e = atomicJSON(localProgramRecord(), existing); e != nil {
			return nil, e
		}
		return map[string]any{"prepared": true, "reused": true, "programId": info.ID, "objectSHA256": localObjectKey()}, nil
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if recordError != nil && !os.IsNotExist(recordError) {
		return nil, recordError
	}
	k := &NativeKernel{}
	alias := "flux-bpf-prepare:" + localObjectKey()
	if text, e := k.run("ip", "", "-j", "link", "show", "dev", localPrepareDevice); e == nil {
		var links []map[string]any
		if e = json.Unmarshal([]byte(text), &links); e != nil {
			return nil, e
		}
		if len(links) != 1 || links[0]["ifalias"] != alias {
			return nil, fmt.Errorf("foreign BPF preparation device")
		}
		if _, e = k.run("ip", "", "link", "del", localPrepareDevice); e != nil {
			return nil, e
		}
	} else if !strings.Contains(e.Error(), "does not exist") && !strings.Contains(e.Error(), "Cannot find") {
		return nil, e
	}
	directory, e := os.MkdirTemp(localPrepareDirectory, "object-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(directory)
	object := filepath.Join(directory, "local_restore.o")
	if e = os.WriteFile(object, localRestoreObject, 0600); e != nil {
		return nil, e
	}
	if _, e = k.run("ip", "", "link", "add", localPrepareDevice, "type", "ifb"); e != nil {
		return nil, e
	}
	defer func() {
		if _, e := k.run("ip", "", "link", "del", localPrepareDevice); e != nil && failure == nil {
			failure = e
		}
	}()
	if _, e = k.run("ip", "", "link", "set", "dev", localPrepareDevice, "alias", alias); e != nil {
		return nil, e
	}
	for _, args := range [][]string{
		{"qdisc", "add", "dev", localPrepareDevice, "clsact"},
		{"filter", "add", "dev", localPrepareDevice, "ingress", "matchall", "action", "ct", "zone", "0", "pipe"},
		{"filter", "add", "dev", localPrepareDevice, "egress", "protocol", "all", "pref", "1", "bpf", "da", "obj", object, "section", "tc"},
	} {
		if _, e = k.run("tc", "", args...); e != nil {
			return nil, e
		}
	}
	text, e := k.run("tc", "", "-j", "filter", "show", "dev", localPrepareDevice, "egress")
	if e != nil {
		return nil, e
	}
	var rows []struct {
		Options struct {
			Prog struct {
				ID uint32 `json:"id"`
			} `json:"prog"`
		} `json:"options"`
	}
	if e = json.Unmarshal([]byte(text), &rows); e != nil {
		return nil, e
	}
	var id uint32
	for _, row := range rows {
		if row.Options.Prog.ID != 0 {
			if id != 0 {
				return nil, fmt.Errorf("ambiguous BPF preparation filter")
			}
			id = row.Options.Prog.ID
		}
	}
	if id == 0 {
		return nil, fmt.Errorf("tc did not expose prepared BPF program id")
	}
	program, e := localProgramFD(id)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(program)
	info, e := localProgramDetails(program)
	if e != nil {
		return nil, e
	}
	if info.Type != 3 || info.ID != id {
		return nil, fmt.Errorf("unexpected BPF preparation program type")
	}
	record := preparedProgram{Version: 1, Phase: "prepared", ObjectSHA256: localObjectKey(), BootID: boot, ID: info.ID, Tag: hex.EncodeToString(info.Tag[:])}
	if e = atomicJSON(localProgramRecord(), record); e != nil {
		return nil, e
	}
	if e = pinLocalProgram(program, localProgramPin()); e != nil {
		return nil, e
	}
	if e = os.Chmod(localProgramPin(), 0600); e != nil {
		return nil, e
	}
	record.Phase = "ready"
	if e = atomicJSON(localProgramRecord(), record); e != nil {
		return nil, e
	}
	return map[string]any{"prepared": true, "reused": false, "programId": info.ID, "objectSHA256": localObjectKey()}, nil
}
