//go:build linux

package engine

import (
	"context"
	"syscall"
)

func (k *IPTables) StartAddressWatcher(ctx context.Context) error {
	if k.P1 == nil {
		return nil
	}
	a := k.P1
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if e != nil {
		return e
	}
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 | 0x10 | 0x100}); e != nil {
		syscall.Close(fd)
		return e
	}
	a.addressDirty.Store(true)
	go func() { <-ctx.Done(); syscall.Close(fd) }()
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, _, err := syscall.Recvfrom(fd, buffer, 0)
			if err != nil {
				return
			}
			if n > 0 {
				a.addressDirty.Store(true)
			}
		}
	}()
	return nil
}
