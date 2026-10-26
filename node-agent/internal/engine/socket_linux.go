//go:build linux

package engine

import "syscall"

func socketInterface(name string) func(string, string, syscall.RawConn) error {
	return socketPolicy(name, 0)
}
func socketPolicy(name string, mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var result error
		e := conn.Control(func(fd uintptr) {
			if name != "" {
				result = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
			}
			if result == nil && mark != 0 {
				result = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			}
		})
		if e != nil {
			return e
		}
		return result
	}
}
