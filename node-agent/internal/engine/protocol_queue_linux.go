//go:build linux

package engine

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"syscall"
	"time"
)

type protocolSocket struct {
	fd     int
	parent *protocolEngine
}

func nfqMessage(typ uint16, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint16(b[18:], protocolQueue)
	copy(b[20:], payload)
	return b
}
func (q *protocolSocket) send(b []byte) error {
	return syscall.Sendto(q.fd, b, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}
func startProtocolQueue(p *protocolEngine) (protocolQueueIO, error) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 12)
	if e != nil {
		return nil, e
	}
	q := &protocolSocket{fd: fd, parent: p}
	fail := func(e error) (protocolQueueIO, error) { syscall.Close(fd); return nil, e }
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return fail(e)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	timeout := syscall.NsecToTimeval(int64(2 * time.Second))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	// Bind only our queue. Never PF_UNBIND another process's queues.
	for i, attrs := range [][]byte{
		nativeAttribute(1, []byte{1, 0, 0, 0}),
		append(append(append(nativeAttribute(2, []byte{0, 0, 0xff, 0xfb, 2}), nativeAttribute(3, []byte{0, 0, 0x10, 0})...), nativeAttribute(4, []byte{0, 0, 0, 6})...), nativeAttribute(5, []byte{0, 0, 0, 6})...),
	} {
		if e = q.send(nfqMessage(0x302, 5, uint32(i+1), attrs)); e != nil {
			return fail(e)
		}
		buf := make([]byte, 8192)
		n, _, e := syscall.Recvfrom(fd, buf, 0)
		if e != nil {
			return fail(e)
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return fail(e)
		}
		ok := false
		for _, m := range msgs {
			if m.Header.Seq == uint32(i+1) && m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code != 0 {
					return fail(fmt.Errorf("NFQUEUE bind/config: %w", syscall.Errno(-code)))
				}
				ok = true
			}
		}
		if !ok {
			return fail(fmt.Errorf("NFQUEUE config acknowledgement missing"))
		}
	}
	timeout = syscall.NsecToTimeval(int64(50 * time.Millisecond))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)
	return q, nil
}
func (q *protocolSocket) start() { go q.loop() }
func (q *protocolSocket) close() { _ = syscall.Close(q.fd) }
func (q *protocolSocket) verdict(pkt queuedProtocolPacket, class byte, blocked, cache bool) error {
	var b [52]byte
	return q.send(encodeProtocolVerdict(b[:], pkt, class, blocked, cache))
}
func protocolVerdictPacket(pkt queuedProtocolPacket, class byte, blocked, cache bool) []byte {
	return encodeProtocolVerdict(make([]byte, 52), pkt, class, blocked, cache)
}
func encodeProtocolVerdict(b []byte, pkt queuedProtocolPacket, class byte, blocked, cache bool) []byte {
	size := 32
	if cache {
		size = 52
	}
	b = b[:size]
	clear(b)
	binary.NativeEndian.PutUint32(b, uint32(size))
	binary.NativeEndian.PutUint16(b[4:], 0x301)
	binary.NativeEndian.PutUint16(b[6:], 1)
	binary.BigEndian.PutUint16(b[18:], protocolQueue)
	binary.NativeEndian.PutUint16(b[20:], 12)
	binary.NativeEndian.PutUint16(b[22:], 2)
	verdict := uint32(1)
	if blocked {
		verdict = 0
	}
	binary.BigEndian.PutUint32(b[24:], verdict)
	binary.BigEndian.PutUint32(b[28:], pkt.id)
	if cache {
		// CTA_MARK is masked XOR: never put the high forwarding token in value.
		mark := uint32(0x10) | uint32(class)
		if blocked {
			mark |= 8
		}
		binary.NativeEndian.PutUint16(b[32:], 20)
		binary.NativeEndian.PutUint16(b[34:], 0x800b)
		binary.NativeEndian.PutUint16(b[36:], 8)
		binary.NativeEndian.PutUint16(b[38:], 8)
		binary.BigEndian.PutUint32(b[40:], mark)
		binary.NativeEndian.PutUint16(b[44:], 8)
		binary.NativeEndian.PutUint16(b[46:], 21)
		binary.BigEndian.PutUint32(b[48:], protocolMask)
	}
	return b
}

func parseProtocolQueue(data []byte) (queuedProtocolPacket, error) {
	p := queuedProtocolPacket{}
	if len(data) < 4 || binary.BigEndian.Uint16(data[2:4]) != protocolQueue {
		return p, fmt.Errorf("unexpected NFQUEUE")
	}
	p.family = data[0]
	seen := false
	seenCTID := false
	e := protocolAttributes(data[4:], func(t uint16, b []byte) error {
		switch t {
		case 1:
			if len(b) < 7 {
				return fmt.Errorf("short queue packet header")
			}
			p.id = binary.BigEndian.Uint32(b)
			seen = true
		case 10:
			p.data = b
		case 13:
			if len(b) != 4 {
				return fmt.Errorf("invalid caplen")
			}
			p.truncated = binary.BigEndian.Uint32(b) > 65531
		case 11:
			return protocolAttributes(b, func(k uint16, v []byte) error {
				switch k {
				case 8:
					if len(v) != 4 {
						return fmt.Errorf("invalid connmark")
					}
					p.mark = binary.BigEndian.Uint32(v)
				case 12:
					if len(v) != 4 {
						return fmt.Errorf("invalid conntrack ID")
					}
					p.ctid = binary.BigEndian.Uint32(v)
					seenCTID = true
				case 1:
					h := fnv.New64a()
					_, _ = h.Write(v)
					p.tuple = h.Sum64()
				}
				return nil
			})
		}
		return nil
	})
	if e != nil {
		return p, e
	}
	if !seen || !seenCTID || p.data == nil || p.tuple == 0 || (p.mark&0xff000000 != 0xf1000000 && p.mark&0xff000000 != 0xf2000000) {
		return p, fmt.Errorf("NFQUEUE missing owned conntrack metadata")
	}
	return p, nil
}
func (q *protocolSocket) loop() {
	buf := make([]byte, 256*1024)
	var messageBuf [32]syscall.NetlinkMessage
	for {
		n, _, flags, from, e := syscall.Recvmsg(q.fd, buf, nil, 0)
		if e == syscall.EINTR {
			continue
		}
		if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
			q.parent.tick()
			continue
		}
		if e != nil {
			q.parent.mu.Lock()
			q.parent.err = e.Error()
			q.parent.ready = false
			q.parent.mu.Unlock()
			q.close()
			return
		}
		source, ok := from.(*syscall.SockaddrNetlink)
		if !ok || source.Pid != 0 || flags&syscall.MSG_TRUNC != 0 {
			continue
		}
		msgs, e := protocolMessagesInto(buf[:n], messageBuf[:0])
		if e != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type == 0x300 {
				pkt, e := parseProtocolQueue(m.Data)
				if e == nil {
					q.parent.handle(pkt)
				} else {
					_ = q.verdict(pkt, 1, true, false)
				}
			} else if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 && int32(binary.NativeEndian.Uint32(m.Data)) != 0 {
				q.parent.mu.Lock()
				q.parent.err = "NFQUEUE verdict rejected"
				q.parent.ready = false
				q.parent.mu.Unlock()
				q.close()
				return
			}
		}
		q.parent.tick()
	}
}

func protocolMessages(b []byte) ([]syscall.NetlinkMessage, error) {
	return protocolMessagesInto(b, nil)
}
func protocolMessagesInto(b []byte, out []syscall.NetlinkMessage) ([]syscall.NetlinkMessage, error) {
	for len(b) > 0 {
		if len(b) < 16 {
			return nil, fmt.Errorf("short queue message")
		}
		size := int(binary.NativeEndian.Uint32(b))
		aligned := (size + 3) &^ 3
		if size < 16 || size > len(b) {
			return nil, fmt.Errorf("truncated queue message")
		}
		if aligned > len(b) {
			if size != len(b) {
				return nil, fmt.Errorf("invalid queue message padding")
			}
			aligned = size
		}
		out = append(out, syscall.NetlinkMessage{Header: syscall.NlMsghdr{Len: uint32(size), Type: binary.NativeEndian.Uint16(b[4:]), Seq: binary.NativeEndian.Uint32(b[8:])}, Data: b[16:size]})
		b = b[aligned:]
	}
	return out, nil
}
