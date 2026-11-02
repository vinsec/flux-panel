package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Classification is bounded protocol recognition, not TLS termination or DPI
// of encrypted application content. UNKNOWN is always allowed and observable.
type ProtocolFilter struct {
	HTTP    bool   `json:"http,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	SOCKS   bool   `json:"socks,omitempty"`
	Unknown string `json:"unknown"`
}

func (p ProtocolFilter) Enabled() bool { return p.HTTP || p.TLS || p.SOCKS }
func (s Spec) protocolPolicy() ProtocolFilter {
	if s.AdvancedOptions == nil || s.ProtocolFilter == nil {
		return ProtocolFilter{Unknown: "allow"}
	}
	return *s.ProtocolFilter
}
func (p ProtocolFilter) blocked(class byte) bool {
	return class == 2 && p.HTTP || class == 3 && p.TLS || class == 4 && p.SOCKS
}
func protocolName(class byte) string {
	switch class {
	case 2:
		return "HTTP"
	case 3:
		return "TLS"
	case 4:
		return "SOCKS"
	}
	return "UNKNOWN"
}

// class 0 requests more prefix bytes; 1 is a final UNKNOWN decision.
func recognizeProtocol(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} {
		m := []byte(method)
		if bytes.HasPrefix(b, m) {
			return 2
		}
		if bytes.HasPrefix(m, b) {
			return 0
		}
	}
	if b[0] == 0x16 {
		if len(b) < 3 {
			return 0
		}
		if b[1] != 3 || b[2] > 4 || b[2] < 1 {
			return 1
		}
		if len(b) < 6 {
			return 0
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if n < 4 || n > 18432 || b[5] != 1 {
			return 1
		}
		return 3
	}
	if b[0] == 5 {
		if len(b) < 2 {
			return 0
		}
		n := int(b[1])
		if n == 0 {
			return 1
		}
		if len(b) < n+2 {
			return 0
		}
		// Match the panel-maintained GOST's supported authentication methods.
		// Private/unknown-only method lists are not enough evidence to block
		// an opaque stream under the UNKNOWN-allow contract.
		for _, method := range b[2 : n+2] {
			if method == 0 || method == 2 {
				return 4
			}
		}
		return 1
	}
	if b[0] == 4 {
		if len(b) < 8 {
			return 0
		}
		if b[1] != 1 && b[1] != 2 || binary.BigEndian.Uint16(b[2:4]) == 0 {
			return 1
		}
		return 4
	}
	return 1
}

type inspectedPacket struct {
	seq         uint32
	syn         bool
	tcp         bool
	payload     []byte
	unsupported bool
}

func inspectPacket(b []byte) inspectedPacket {
	p := inspectedPacket{}
	if len(b) < 1 {
		p.unsupported = true
		return p
	}
	off, proto := 0, byte(0)
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			p.unsupported = true
			return p
		}
		off = int(b[0]&15) * 4
		proto = b[9]
		if off < 20 || off > len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			p.unsupported = true
			return p
		}
	case 6:
		if len(b) < 40 {
			p.unsupported = true
			return p
		}
		off, proto = 40, b[6]
		for n := 0; n < 8 && proto != 6 && proto != 17; n++ {
			if off+8 > len(b) {
				p.unsupported = true
				return p
			}
			next := b[off]
			switch proto {
			case 0, 60:
				off += (int(b[off+1]) + 1) * 8
			case 44:
				if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff9 != 0 {
					p.unsupported = true
					return p
				}
				off += 8
			default:
				p.unsupported = true
				return p
			}
			proto = next
		}
	default:
		p.unsupported = true
		return p
	}
	if proto != 6 {
		p.unsupported = proto != 17
		return p
	}
	if off+20 > len(b) {
		p.unsupported = true
		return p
	}
	h := int(b[off+12]>>4) * 4
	if h < 20 || off+h > len(b) {
		p.unsupported = true
		return p
	}
	p.tcp = true
	p.seq = binary.BigEndian.Uint32(b[off+4 : off+8])
	p.syn = b[off+13]&2 != 0
	if p.syn {
		p.seq++
	}
	p.payload = b[off+h:]
	return p
}
func validateProtocolPolicy(s Spec) error {
	if s.AdvancedOptions == nil || s.ProtocolFilter == nil {
		return nil
	}
	if s.SchemaVersion != 5 {
		return fmt.Errorf("protocol filtering requires schema 5")
	}
	if s.ProtocolFilter.Unknown != "allow" {
		return fmt.Errorf("unknown protocol policy must be allow")
	}
	return nil
}

// NFQUEUE may omit the final datagram/attribute padding after copied payload.
func protocolAttributes(b []byte, visit func(uint16, []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return fmt.Errorf("short queue attribute")
		}
		n := int(binary.NativeEndian.Uint16(b))
		aligned := (n + 3) &^ 3
		if n < 4 || n > len(b) {
			return fmt.Errorf("truncated queue attribute")
		}
		if aligned > len(b) {
			if n != len(b) {
				return fmt.Errorf("invalid queue padding")
			}
			aligned = n
		}
		if e := visit(binary.NativeEndian.Uint16(b[2:])&0x3fff, b[4:n]); e != nil {
			return e
		}
		b = b[aligned:]
	}
	return nil
}
