//go:build linux

package engine

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type localProgramInfo struct {
	Type, ID uint32
	Tag      [8]byte
}

func localBPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	var number uintptr
	switch runtime.GOARCH {
	case "arm64":
		number = 280
	case "amd64":
		number = 321
	default:
		return -1, fmt.Errorf("unsupported BPF architecture")
	}
	fd, _, e := syscall.Syscall(number, cmd, uintptr(attr), size)
	runtime.KeepAlive(attr)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}
func localProgramFD(id uint32) (int, error) {
	attr := [3]uint32{id, 0, 0}
	return localBPF(13, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}
func localProgramDetails(fd int) (localProgramInfo, error) {
	var info localProgramInfo
	attr := struct {
		FD, Size uint32
		Info     uint64
	}{uint32(fd), uint32(unsafe.Sizeof(info)), uint64(uintptr(unsafe.Pointer(&info)))}
	_, e := localBPF(15, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	return info, e
}
func pinLocalProgram(fd int, path string) error {
	p, e := syscall.BytePtrFromString(path)
	if e != nil {
		return e
	}
	attr := struct {
		Path      uint64
		FD, Flags uint32
	}{uint64(uintptr(unsafe.Pointer(p))), uint32(fd), 0}
	_, e = localBPF(6, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(p)
	return e
}
func inspectLocalProgramPin(path string) (localProgramInfo, error) {
	var info localProgramInfo
	st, e := os.Lstat(path)
	if e != nil {
		return info, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !sameObjectOwner(st) {
		return info, fmt.Errorf("unsafe local BPF pin")
	}
	p, e := syscall.BytePtrFromString(path)
	if e != nil {
		return info, e
	}
	attr := struct {
		Path      uint64
		FD, Flags uint32
	}{uint64(uintptr(unsafe.Pointer(p))), 0, 0}
	fd, e := localBPF(7, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(p)
	if e != nil {
		return info, e
	}
	defer syscall.Close(fd)
	return localProgramDetails(fd)
}
func localBPFFilesystem() error {
	var st syscall.Statfs_t
	if e := syscall.Statfs(localPinDirectory, &st); e != nil {
		return e
	}
	if uint64(st.Type) != 0xcafe4a11 {
		return fmt.Errorf("administrator must mount bpffs at /sys/fs/bpf before preparation")
	}
	return nil
}
