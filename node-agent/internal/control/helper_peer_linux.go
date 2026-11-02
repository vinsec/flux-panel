//go:build linux

package control

import (
	"net"
	"syscall"
)

func helperPeerAllowed(conn *net.UnixConn, uid uint32) bool {
	raw, e := conn.SyscallConn()
	if e != nil {
		return false
	}
	allowed := false
	_ = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e == nil && (cred.Uid == uid || cred.Uid == 0) {
			allowed = true
		}
	})
	return allowed
}
