package engine

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Captured from an independent Python NETLINK_NETFILTER query on the offline
// Debian 6.12 VM. Kernel counter initialized through nft to 12 packets/1234 B.
const nativeCounterCapture = "010000020e00010046505f4e415449564500000027000200635f373035303034396562623234396431316164613032623233646665313031333500000c0006000000000000000001080003000000000108000500000000001c0004000c00010000000000000004d20c000200000000000000000c33000800002d4650345f55507c3139322e302e322e312c307866323030303130307c666c75783a76323a315f315f303a75700000"

func TestNativeNetlinkCapturedCounter(t *testing.T) {
	b, e := hex.DecodeString(nativeCounterCapture)
	if e != nil {
		t.Fatal(e)
	}
	c, e := nativeCounterObject(b)
	if e != nil {
		t.Fatal(e)
	}
	if c.Bytes != 1234 || c.Packets != 12 || c.Comment != "FP4_UP|192.0.2.1,0xf2000100|flux:v2:1_1_0:up" {
		t.Fatal(c)
	}
	if r, e := decodeNativeCounter(c); e != nil || r.Set != "FP4_UP" || r.Key != "192.0.2.1,0xf2000100" {
		t.Fatal(r, e)
	}
	for cut := 0; cut < len(b); cut++ {
		if _, e = nativeCounterObject(b[:cut]); e == nil {
			t.Fatalf("truncation at %d accepted", cut)
		}
	}
	const huge = uint64(1)<<63 + 29
	if e = nativeAttributes(b[4:], func(k uint16, v []byte) error {
		if k == 4 {
			return nativeAttributes(v, func(k uint16, v []byte) error {
				if k == 1 {
					binary.BigEndian.PutUint64(v, huge)
				}
				return nil
			})
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	c, e = nativeCounterObject(b)
	if e != nil || c.Bytes != huge {
		t.Fatal(c, e)
	}
}
func TestNativeNetlinkRejectsForeignOrAmbiguousObjects(t *testing.T) {
	b, _ := hex.DecodeString(nativeCounterCapture)
	for _, suffix := range [][]byte{nativeAttribute(1, []byte("another_table\x00")), nativeAttribute(8, []byte{0, 2, 'x', 0}), {3, 0, 1, 0}} {
		if _, e := nativeCounterObject(append(append([]byte{}, b...), suffix...)); e == nil {
			t.Fatal("ambiguous object accepted")
		}
	}
	b[0] = 2
	if _, e := nativeCounterObject(b); e == nil {
		t.Fatal("foreign family accepted")
	}
	for _, bad := range [][]byte{{0, 10, 'x'}, {0, 0}, {0, 2, 'x', 'y'}} {
		if _, e := nativeObjectComment(bad); e == nil {
			t.Fatal("corrupt userdata accepted")
		}
	}
}
