//go:build linux

package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
)

var nativeDumpInterrupted = errors.New("nft counter dump interrupted")

func (n *NativeNFT) readCounterObjects() ([]nativeCounter, error) {
	deadline := time.Now().Add(4 * time.Second)
	for attempt := 0; attempt < 3; attempt++ {
		out, e := nativeCounterDump(deadline)
		if e == nil || !errors.Is(e, nativeDumpInterrupted) && !errors.Is(e, syscall.ENOBUFS) {
			return out, e
		}
	}
	return nil, nativeDumpInterrupted
}
func nativeCounterDump(deadline time.Time) ([]nativeCounter, error) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 12)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(fd)
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	address, e := syscall.Getsockname(fd)
	if e != nil {
		return nil, e
	}
	port := address.(*syscall.SockaddrNetlink).Pid
	payload := []byte{1, 0, 0, 0}
	payload = append(payload, nativeAttribute(1, append([]byte(nativeTable), 0))...)
	payload = append(payload, nativeAttribute(3, []byte{0, 0, 0, 1})...)
	request := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], nativeGetObject)
	binary.NativeEndian.PutUint16(request[6:], 0x301)
	binary.NativeEndian.PutUint32(request[8:], 1)
	copy(request[16:], payload)
	if e = syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	buffer := make([]byte, 256*1024)
	out := []nativeCounter{}
	total := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("nft counter dump deadline")
		}
		timeout := syscall.NsecToTimeval(remaining.Nanoseconds())
		if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); e != nil {
			return nil, e
		}
		count, _, flags, from, e := syscall.Recvmsg(fd, buffer, nil, 0)
		if e == syscall.EINTR {
			continue
		}
		if e != nil {
			return nil, e
		}
		source, ok := from.(*syscall.SockaddrNetlink)
		if !ok || source.Pid != 0 || flags&syscall.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("invalid nft dump sender or truncated datagram")
		}
		total += count
		if total > 256*1024*1024 || count == 0 {
			return nil, fmt.Errorf("nft counter dump size limit")
		}
		b := buffer[:count]
		for len(b) > 0 {
			if len(b) < 16 {
				return nil, fmt.Errorf("short nft netlink header")
			}
			size := int(binary.NativeEndian.Uint32(b))
			aligned := (size + 3) &^ 3
			if size < 16 || aligned > len(b) {
				return nil, fmt.Errorf("truncated nft netlink message")
			}
			typ, flag := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
			seq, pid := binary.NativeEndian.Uint32(b[8:]), binary.NativeEndian.Uint32(b[12:])
			data := b[16:size]
			if seq != 1 || pid != 0 && pid != port {
				return nil, fmt.Errorf("unexpected nft dump sequence/port")
			}
			if flag&0x10 != 0 {
				return nil, nativeDumpInterrupted
			}
			switch typ {
			case syscall.NLMSG_NOOP:
			case syscall.NLMSG_ERROR, syscall.NLMSG_DONE:
				if len(data) < 4 {
					return nil, fmt.Errorf("short nft dump result")
				}
				code := int32(binary.NativeEndian.Uint32(data))
				if code != 0 {
					if code < 0 {
						return nil, syscall.Errno(-code)
					}
					return nil, fmt.Errorf("invalid nft dump result")
				}
				if typ == syscall.NLMSG_DONE {
					return out, nil
				}
			case nativeNewObject:
				c, e := nativeCounterObject(data)
				if e != nil {
					return nil, e
				}
				out = append(out, c)
				if len(out) > 1<<20 {
					return nil, fmt.Errorf("nft counter object limit")
				}
			default:
				return nil, fmt.Errorf("unexpected nft dump message")
			}
			b = b[aligned:]
		}
	}
}
