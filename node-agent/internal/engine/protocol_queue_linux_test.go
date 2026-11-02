//go:build linux

package engine

import (
	"encoding/binary"
	"testing"
)

func TestProtocolQueueIdentityAndUnalignedMessage(t *testing.T) {
	packet := append(nativeAttribute(1, []byte{0, 0, 0, 1, 8, 0, 0}), nativeAttribute(10, []byte{1, 2, 3})...)
	ct := append(nativeAttribute(8, []byte{0xf2, 0, 1, 0}), nativeAttribute(1, []byte{1, 2, 3, 4})...)
	body := []byte{2, 0, 0, 0}
	binary.BigEndian.PutUint16(body[2:], protocolQueue)
	missing := append(append(append([]byte{}, body...), packet...), nativeAttribute(0x800b, ct)...)
	if _, e := parseProtocolQueue(missing); e == nil {
		t.Fatal("missing conntrack ID accepted")
	}
	ct = append(ct, nativeAttribute(12, []byte{0, 0, 0, 0})...)
	full := append(append(append([]byte{}, body...), packet...), nativeAttribute(0x800b, ct)...)
	if p, e := parseProtocolQueue(full); e != nil || p.ctid != 0 || p.id != 1 {
		t.Fatal("present zero ID is valid", p, e)
	}
	raw := make([]byte, 19)
	binary.NativeEndian.PutUint32(raw, 19)
	binary.NativeEndian.PutUint16(raw[4:], 0x300)
	copy(raw[16:], []byte{1, 2, 3})
	msgs, e := protocolMessages(raw)
	if e != nil || len(msgs) != 1 || len(msgs[0].Data) != 3 {
		t.Fatal("final message padding must be optional", e)
	}
}

func TestProtocolVerdictMaskedMarkPreservesToken(t *testing.T) {
	for _, class := range []byte{1, 2, 3, 4} {
		for _, blocked := range []bool{false, true} {
			old := uint32(0xf20001e0)
			packet := protocolVerdictPacket(queuedProtocolPacket{id: 1, mark: old}, class, blocked, true)
			var value, mask uint32
			if e := protocolAttributes(packet[20:], func(k uint16, b []byte) error {
				if k == 11 {
					return protocolAttributes(b, func(k uint16, b []byte) error {
						if k == 8 {
							value = binary.BigEndian.Uint32(b)
						}
						if k == 21 {
							mask = binary.BigEndian.Uint32(b)
						}
						return nil
					})
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			want := uint32(0x10) | uint32(class)
			if blocked {
				want |= 8
			}
			if mask != protocolMask || value&^mask != 0 || value != want {
				t.Fatal("masked XOR must contain only decision bits", mask, value)
			}
			after := (old &^ mask) ^ value
			if after&^mask != old&^mask || ((after&^mask)^value) != after {
				t.Fatal("forwarding token/auxiliary bits changed or verdict is not idempotent", old, after)
			}
		}
	}
}
