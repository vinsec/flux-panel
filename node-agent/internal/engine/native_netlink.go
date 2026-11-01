package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Read-only NFT_MSG_GETOBJ wire format from Linux UAPI nf_tables.h.
// Only named counter objects in our inet table are accepted. No RESET, ADD or
// DELETE request is used by the sampler, including on retry.
const nativeGetObject = 10<<8 | 19
const nativeNewObject = 10<<8 | 18

func nativeAttribute(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}
func nativeAttributes(b []byte, visit func(uint16, []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return fmt.Errorf("short nft attribute")
		}
		n := int(binary.NativeEndian.Uint16(b))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(b) {
			return fmt.Errorf("truncated nft attribute")
		}
		if e := visit(binary.NativeEndian.Uint16(b[2:])&0x3fff, b[4:n]); e != nil {
			return e
		}
		b = b[aligned:]
	}
	return nil
}
func nativeString(b []byte) (string, error) {
	if len(b) < 1 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
		return "", fmt.Errorf("invalid nft string")
	}
	return string(b[:len(b)-1]), nil
}
func nativeObjectComment(b []byte) (string, error) {
	// libnftnl's object comment is userdata TLV type 0, with an 8-bit length
	// and a NUL-terminated value. Unknown TLVs are skipped, not executed.
	comment := ""
	for len(b) > 0 {
		if len(b) < 2 || int(b[1])+2 > len(b) {
			return "", fmt.Errorf("truncated nft userdata")
		}
		n := int(b[1])
		if b[0] == 0 {
			if comment != "" {
				return "", fmt.Errorf("duplicate nft comment")
			}
			var e error
			comment, e = nativeString(b[2 : 2+n])
			if e != nil {
				return "", e
			}
		}
		b = b[n+2:]
	}
	if comment == "" {
		return "", fmt.Errorf("missing nft counter ownership")
	}
	return comment, nil
}
func nativeCounterObject(payload []byte) (nativeCounter, error) {
	return counterObjectForTable(payload, nativeTable)
}
func counterObjectForTable(payload []byte, expectedTable string) (nativeCounter, error) {
	var c nativeCounter
	if len(payload) < 4 || payload[0] != 1 || payload[1] != 0 {
		return c, fmt.Errorf("unexpected nft object family/version")
	}
	seen := uint16(0)
	table := ""
	kind := uint32(0)
	e := nativeAttributes(payload[4:], func(t uint16, b []byte) error {
		if t != 1 && t != 2 && t != 3 && t != 4 && t != 8 {
			return nil
		}
		if seen&(1<<t) != 0 {
			return fmt.Errorf("duplicate nft object attribute")
		}
		seen |= 1 << t
		var e error
		switch t {
		case 1:
			table, e = nativeString(b)
		case 2:
			c.Name, e = nativeString(b)
		case 3:
			if len(b) != 4 {
				return fmt.Errorf("invalid nft object kind")
			}
			kind = binary.BigEndian.Uint32(b)
		case 8:
			if len(b) > 256 {
				return fmt.Errorf("oversize nft userdata")
			}
			c.Comment, e = nativeObjectComment(b)
		case 4:
			counts := uint8(0)
			e = nativeAttributes(b, func(k uint16, v []byte) error {
				if k != 1 && k != 2 {
					return nil
				}
				if counts&(1<<k) != 0 || len(v) != 8 {
					return fmt.Errorf("invalid nft counter value")
				}
				counts |= 1 << k
				if k == 1 {
					c.Bytes = binary.BigEndian.Uint64(v)
				} else {
					c.Packets = binary.BigEndian.Uint64(v)
				}
				return nil
			})
			if e == nil && counts != 6 {
				e = fmt.Errorf("incomplete nft counter")
			}
		}
		return e
	})
	if e != nil {
		return c, e
	}
	if seen != uint16(1<<1|1<<2|1<<3|1<<4|1<<8) || table != expectedTable || kind != 1 {
		return c, fmt.Errorf("unexpected nft counter scope")
	}
	return c, nil
}
