package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const localPinDirectory = "/sys/fs/bpf/flux-local-shaping"
const localPrepareDirectory = "/run/flux-agent-bpf"
const localPrepareDevice = "fp4bpfload"

type preparedProgram struct {
	Version      int    `json:"version"`
	Phase        string `json:"phase"`
	ObjectSHA256 string `json:"objectSHA256"`
	BootID       string `json:"bootId"`
	ID           uint32 `json:"programId"`
	Tag          string `json:"programTag"`
}

var localObjectIdentity struct {
	sync.Once
	key string
}

func localObjectKey() string {
	localObjectIdentity.Do(func() { sum := sha256.Sum256(localRestoreObject); localObjectIdentity.key = hex.EncodeToString(sum[:]) })
	return localObjectIdentity.key
}
func localProgramPin() string { return filepath.Join(localPinDirectory, "restore_"+localObjectKey()) }
func localProgramRecord() string {
	return filepath.Join(localPrepareDirectory, localObjectKey()+".json")
}
func localBootID() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b)), e
}
func privateLocalDirectory(path string, create bool) error {
	if create {
		if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
			return e
		}
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || !sameObjectOwner(st) {
		return fmt.Errorf("unsafe local preparation directory: %s", path)
	}
	return nil
}
func readPreparedRecord() (preparedProgram, error) {
	var record preparedProgram
	if e := privateLocalDirectory(localPrepareDirectory, false); e != nil {
		return record, e
	}
	st, e := os.Lstat(localProgramRecord())
	if e != nil {
		return record, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !sameObjectOwner(st) || st.Size() > 4096 {
		return record, fmt.Errorf("unsafe local preparation record")
	}
	b, e := os.ReadFile(localProgramRecord())
	if e != nil {
		return record, e
	}
	e = json.Unmarshal(b, &record)
	return record, e
}
func checkPreparedRecord(record preparedProgram, info localProgramInfo, boot string, ready bool) error {
	if record.Version != 1 || record.ObjectSHA256 != localObjectKey() || record.BootID != boot || record.ID == 0 || record.Tag != hex.EncodeToString(info.Tag[:]) || record.ID != info.ID || info.Type != 3 {
		return fmt.Errorf("prepared local BPF identity mismatch")
	}
	if ready && record.Phase != "ready" {
		return fmt.Errorf("local BPF preparation has not committed")
	}
	if record.Phase != "ready" && record.Phase != "prepared" {
		return fmt.Errorf("unknown local BPF preparation phase")
	}
	return nil
}

// No module-BTF enumeration or program load is done here. This opens only a
// root-owned pin prepared by this exact Agent object on the current boot.
func preparedLocalProgram() (string, error) {
	if e := privateLocalDirectory(localPinDirectory, false); e != nil {
		return "", e
	}
	record, e := readPreparedRecord()
	if e != nil {
		return "", e
	}
	boot, e := localBootID()
	if e != nil {
		return "", e
	}
	info, e := inspectLocalProgramPin(localProgramPin())
	if e != nil {
		return "", e
	}
	if e = checkPreparedRecord(record, info, boot, true); e != nil {
		return "", e
	}
	return localProgramPin(), nil
}
