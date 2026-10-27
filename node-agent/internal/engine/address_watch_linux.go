//go:build linux

package engine

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
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
		ignored := map[uint32]bool{}
		for {
			n, _, err := syscall.Recvfrom(fd, buffer, 0)
			if err != nil {
				return
			}
			if n > 0 {
				messages, e := syscall.ParseNetlinkMessage(buffer[:n])
				if e != nil {
					a.addressDirty.Store(true)
					continue
				}
				for _, m := range messages {
					if relevantAddressEvent(m, ignored) {
						a.addressDirty.Store(true)
					}
				}
			}
		}
	}()
	return nil
}

// IFB and the down preflight probe are owned, addressless data-path devices.
// Ignore their link/address notifications rather than caching a fresh physical
// inventory after an old binding snapshot (which can lose DAD/removal events).
// External IFB deletion/down/replacement is checked by runtimeContractsChanged.
func relevantAddressEvent(m syscall.NetlinkMessage, ignored map[uint32]bool) bool {
	switch m.Header.Type {
	case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
		if len(m.Data) < syscall.SizeofIfInfomsg {
			return true
		}
		index := binary.NativeEndian.Uint32(m.Data[4:8])
		attrs, e := syscall.ParseNetlinkRouteAttr(&m)
		if e != nil {
			return true
		}
		for _, attr := range attrs {
			if attr.Attr.Type == syscall.IFLA_IFNAME {
				name := strings.TrimRight(string(attr.Value), "\x00")
				if name == shapingDevice || name == localProbeDevice {
					if len(ignored) > 128 {
						clear(ignored)
					}
					ignored[index] = true
					return false
				}
				delete(ignored, index)
				return true
			}
		}
		return true
	case syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
		if len(m.Data) < syscall.SizeofIfAddrmsg {
			return true
		}
		index := binary.NativeEndian.Uint32(m.Data[4:8])
		if ignored[index] {
			return false
		}
		if iface, e := net.InterfaceByIndex(int(index)); e == nil && (iface.Name == shapingDevice || iface.Name == localProbeDevice) {
			ignored[index] = true
			return false
		}
		return true
	case syscall.NLMSG_DONE, syscall.NLMSG_NOOP:
		return false
	default:
		return true
	}
}
