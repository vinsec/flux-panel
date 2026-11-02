//go:build linux

package engine

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func linkEvent(kind uint16, index uint32, name string) syscall.NetlinkMessage {
	b := make([]byte, syscall.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(b[4:8], index)
	value := append([]byte(name), 0)
	size := 4 + len(value)
	attr := make([]byte, (size+3)&^3)
	binary.NativeEndian.PutUint16(attr, uint16(size))
	binary.NativeEndian.PutUint16(attr[2:], syscall.IFLA_IFNAME)
	copy(attr[4:], value)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: kind}, Data: append(b, attr...)}
}
func addrEvent(kind uint16, index uint32) syscall.NetlinkMessage {
	b := make([]byte, syscall.SizeofIfAddrmsg)
	binary.NativeEndian.PutUint32(b[4:8], index)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: kind}, Data: b}
}
func TestAddressWatcherNeverLosesPhysicalDeletionAfterOwnedLinkEvents(t *testing.T) {
	ignored := map[uint32]bool{}
	if relevantAddressEvent(linkEvent(syscall.RTM_NEWLINK, 9001, shapingDevice), ignored) {
		t.Fatal("self IFB creates another gated rebuild")
	}
	if relevantAddressEvent(addrEvent(syscall.RTM_NEWADDR, 9001), ignored) {
		t.Fatal("IFB autoconfiguration is a physical binding event")
	}
	if !relevantAddressEvent(addrEvent(syscall.RTM_DELADDR, 9002), ignored) {
		t.Fatal("physical IPv6 removal suppressed")
	}
	if !relevantAddressEvent(linkEvent(syscall.RTM_NEWLINK, 9001, "r0"), ignored) || !relevantAddressEvent(addrEvent(syscall.RTM_DELADDR, 9001), ignored) {
		t.Fatal("reused physical index remains ignored")
	}
	if !relevantAddressEvent(syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWADDR}}, ignored) {
		t.Fatal("malformed event must force resynchronization")
	}
}
