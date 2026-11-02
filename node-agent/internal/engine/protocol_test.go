package engine

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestProtocolBoundedRecognition(t *testing.T) {
	for _, row := range []struct {
		b     []byte
		class byte
	}{{[]byte("GE"), 0}, {[]byte("GET / HTTP/1.1\r\n"), 2}, {[]byte("GETTING opaque"), 1}, {[]byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, 3}, {[]byte{5, 1}, 0}, {[]byte{5, 1, 0}, 4}, {[]byte{5, 1, 0x80}, 1}, {[]byte{5, 2, 0x80, 2}, 4}, {[]byte{4, 1, 1, 0, 127, 0, 0, 1}, 4}, {[]byte("opaque encryption"), 1}} {
		if c := recognizeProtocol(row.b); c != row.class {
			t.Fatalf("%x -> %d want%d", row.b, c, row.class)
		}
	}
	for _, p := range []ProtocolFilter{{Unknown: "allow"}, {HTTP: true, Unknown: "allow"}, {HTTP: true, TLS: true, SOCKS: true, Unknown: "allow"}} {
		if p.blocked(1) {
			t.Fatal("UNKNOWN must be allowed")
		}
	}
}
func TestProtocolPolicyNeedsVersionedContract(t *testing.T) {
	s := Spec{SchemaVersion: 4, AdvancedOptions: &AdvancedOptions{ProtocolFilter: &ProtocolFilter{HTTP: true, Unknown: "allow"}}}
	if validateProtocolPolicy(s) == nil {
		t.Fatal("old schema accepted")
	}
	s.SchemaVersion = 5
	if validateProtocolPolicy(s) != nil {
		t.Fatal("valid policy rejected")
	}
	if requiredStateFormat(map[string]Spec{"x": s}) != 7 {
		t.Fatal("old executable could silently ignore filter")
	}
}
func TestQueueTailPadding(t *testing.T) {
	for n := 1; n < 12; n++ {
		b := nativeAttribute(10, make([]byte, n))
		size := int(binary.NativeEndian.Uint16(b))
		if e := protocolAttributes(b[:size], func(k uint16, v []byte) error {
			if k != 10 || len(v) != n {
				t.Fatal(k, len(v))
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
}

type recordingProtocolQueue struct {
	class   byte
	blocked bool
	count   int
}

func (q *recordingProtocolQueue) verdict(_ queuedProtocolPacket, c byte, b, cache bool) error {
	q.class = c
	q.blocked = b
	q.count++
	return nil
}
func (*recordingProtocolQueue) close() {}
func (*recordingProtocolQueue) start() {}
func protocolTCP(seq uint32, body []byte) []byte {
	b := make([]byte, 40+len(body))
	b[0] = 0x45
	b[9] = 6
	b[32] = 0x50
	binary.BigEndian.PutUint32(b[24:], seq)
	copy(b[40:], body)
	return b
}
func TestProtocolReassemblyAndLargeGSO(t *testing.T) {
	for _, large := range []bool{false, true} {
		p := (&NativeKernel{}).protocolEngine()
		q := &recordingProtocolQueue{}
		p.io = q
		rules := map[uint32]protocolRule{0xf1000100: {ID: "x", Policy: ProtocolFilter{HTTP: true, Unknown: "allow"}}}
		p.rules.Store(&rules)
		packet := func(seq uint32, b []byte) {
			p.handle(queuedProtocolPacket{mark: 0xf1000100, ctid: 1, tuple: 1, data: protocolTCP(seq, b)})
		}
		if large {
			packet(100, append([]byte("GET / "), bytes.Repeat([]byte("x"), 60000)...))
		} else {
			packet(100, []byte("GE"))
			if q.count != 0 {
				t.Fatal("ambiguous prefix escaped")
			}
			packet(102, []byte("T / HTTP/1.1"))
		}
		if q.class != 2 || !q.blocked || p.held != 0 || p.bodies != 0 {
			t.Fatal("HTTP escaped or buffer leaked", large, q, p.held, p.bodies)
		}
	}
}
func TestProtocolTimeoutAndFlowCapacity(t *testing.T) {
	p := (&NativeKernel{}).protocolEngine()
	q := &recordingProtocolQueue{}
	p.io = q
	rules := map[uint32]protocolRule{0xf1000100: {ID: "x", Policy: ProtocolFilter{HTTP: true, Unknown: "allow"}}}
	p.rules.Store(&rules)
	p.handle(queuedProtocolPacket{mark: 0xf1000100, ctid: 1, tuple: 1, data: protocolTCP(100, []byte("G"))})
	for _, f := range p.flows {
		f.at = time.Now().Add(-time.Second)
	}
	p.tick()
	if q.class != 1 || q.blocked || p.held != 0 || p.bodies != 0 {
		t.Fatal("UNKNOWN timeout contract", q)
	}
	for i := 0; i < 32768; i++ {
		p.flows[protocolKey{id: uint32(i), mark: 0xf1000100, tuple: 2}] = &protocolFlow{class: 1, last: time.Now()}
	}
	p.handle(queuedProtocolPacket{mark: 0xf1000100, ctid: 40000, tuple: 2, data: protocolTCP(100, []byte("G"))})
	if q.class != 1 || q.blocked || p.held != 0 || p.bodies != 0 {
		t.Fatal("capacity must allow UNKNOWN without retaining unreachable buffers", q)
	}
}
func TestProtocolTableOwnership(t *testing.T) {
	for _, comment := range []string{protocolOwner, "foreign:" + protocolOwner} {
		raw := `{"nftables":[{"table":{"family":"inet","name":"FP_PROTOCOL","comment":"` + comment + `"}},{"rule":{"family":"inet","table":"FP_PROTOCOL","chain":"forward","expr":[{"mangle":{"key":{"ct":{"key":"mark"}}}}]}}]}`
		e := validateNativeRules(raw, map[string]map[string]bool{})
		if (e == nil) != (comment == protocolOwner) {
			t.Fatal("owner spoofing", comment, e)
		}
	}
}

// This measures the actual classifier's new-flow path, including flow bookkeeping
// and verdict generation through a recording queue. It does not measure NFQUEUE
// syscalls or claim end-to-end packet latency.
func BenchmarkProtocolInitialDecision(b *testing.B) {
	for _, row := range []struct {
		name    string
		payload []byte
		split   bool
	}{
		{"UNKNOWN", []byte("opaque"), false}, {"HTTP", []byte("GET / HTTP/1.1\r\n\r\n"), false},
		{"TLS", []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, false}, {"SOCKS5", []byte{5, 1, 0}, false},
		{"splitHTTP", []byte("GET / HTTP/1.1\r\n\r\n"), true},
	} {
		b.Run(row.name, func(b *testing.B) {
			p := (&NativeKernel{}).protocolEngine()
			p.io = &recordingProtocolQueue{}
			rules := map[uint32]protocolRule{0xf1000100: {ID: "x", Policy: ProtocolFilter{HTTP: true, TLS: true, SOCKS: true, Unknown: "allow"}}}
			p.rules.Store(&rules)
			packet := queuedProtocolPacket{mark: 0xf1000100, ctid: 1, tuple: 1, data: protocolTCP(100, row.payload)}
			first, last := packet, packet
			first.data = protocolTCP(100, row.payload[:2])
			last.data = protocolTCP(102, row.payload[2:])
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if row.split {
					p.handle(first)
					p.handle(last)
				} else {
					p.handle(packet)
				}
				delete(p.flows, protocolKey{1, 0xf1000100, 1})
			}
		})
	}
}

func TestProtocolFieldsCannotHideInLegacySchema(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, 4} {
		s := Spec{ID: "1_1_0", Revision: 1, SchemaVersion: version, ListenIP: "192.0.2.1", ListenPort: 18000, TargetIP: "192.0.2.2", TargetPort: 19000, AdvancedOptions: &AdvancedOptions{ProtocolFilter: &ProtocolFilter{HTTP: true, Unknown: "allow"}}}
		if _, e := s.Normalize(); e == nil {
			t.Fatal("legacy schema silently accepted protocol policy", version)
		}
		if e := s.Validate(); e == nil {
			t.Fatal("checkpoint accepted legacy protocol policy", version)
		}
	}
}
