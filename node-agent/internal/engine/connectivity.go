package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

type ProbeMetrics struct {
	Sent        int      `json:"sent"`
	Received    int      `json:"received"`
	PacketLoss  float64  `json:"packetLoss"`
	AverageTime *float64 `json:"averageTime"`
	Error       string   `json:"error,omitempty"`
}

func (p *ProbeMetrics) finish(total time.Duration) {
	p.PacketLoss = 100
	if p.Sent > 0 {
		p.PacketLoss = 100 * float64(p.Sent-p.Received) / float64(p.Sent)
	}
	if p.Received > 0 {
		n := total.Seconds() * 1000 / float64(p.Received)
		p.AverageTime = &n
	}
}

func probeDeadline(ctx context.Context) time.Time {
	end := time.Now().Add(600 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(end) {
		end = d
	}
	return end
}

func tcpConnectivity(ctx context.Context, host string, port int, egress EgressPolicy) ProbeMetrics {
	p := ProbeMetrics{}
	var total time.Duration
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		d := net.Dialer{Timeout: 600 * time.Millisecond}
		if egress.Interface != "" {
			d.Control = socketInterface(egress.Interface)
		}
		source := egress.SourceIPv4
		if net.ParseIP(host).To4() == nil {
			source = egress.SourceIPv6
		}
		if source != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
		}
		p.Sent++
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err == nil {
			p.Received++
			total += time.Since(start)
			conn.Close()
		}
	}
	p.finish(total)
	if p.Received == 0 {
		p.Error = "TCP 未连接"
	}
	return p
}

// IPv6 raw ICMP sockets let the kernel supply its pseudo-header checksum.
func echoPacket(kind byte, id, seq int, nonce []byte) []byte {
	p := make([]byte, 8+len(nonce))
	p[0] = kind
	binary.BigEndian.PutUint16(p[4:6], uint16(id))
	binary.BigEndian.PutUint16(p[6:8], uint16(seq))
	copy(p[8:], nonce)
	if kind == 8 {
		var sum uint32
		for i := 0; i+1 < len(p); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
		}
		if len(p)%2 != 0 {
			sum += uint32(p[len(p)-1]) << 8
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(p[2:4], ^uint16(sum))
	}
	return p
}
func echoReplyMatches(body []byte, kind byte, id, seq int, nonce []byte) bool {
	return len(body) == 8+len(nonce) && body[0] == kind && body[1] == 0 && binary.BigEndian.Uint16(body[4:6]) == uint16(id) && binary.BigEndian.Uint16(body[6:8]) == uint16(seq) && bytes.Equal(body[8:], nonce)
}

func icmpConnectivity(ctx context.Context, host string, egress EgressPolicy) ProbeMetrics {
	p := ProbeMetrics{}
	var total time.Duration
	ip, err := netip.ParseAddr(host)
	if err != nil {
		p.Error = "ICMP 目标无效"
		p.finish(0)
		return p
	}
	network, protocol := "ip4:icmp", 1
	request, reply := byte(8), byte(0)
	source := egress.SourceIPv4
	if ip.Is6() {
		network, protocol = "ip6:ipv6-icmp", 58
		request, reply = 128, 129
		source = egress.SourceIPv6
	}
	d := net.Dialer{Timeout: 600 * time.Millisecond}
	if source != "" {
		d.LocalAddr = &net.IPAddr{IP: net.ParseIP(source)}
	}
	if egress.Interface != "" {
		d.Control = socketInterface(egress.Interface)
	}
	conn, err := d.DialContext(ctx, network, host)
	if err != nil {
		p.Error = "无法发送 ICMP"
		p.finish(0)
		return p
	}
	defer conn.Close()
	nonce := make([]byte, 18)
	if _, err = rand.Read(nonce); err != nil {
		p.Error = "无法创建 ICMP 探测"
		p.finish(0)
		return p
	}
	id := int(binary.BigEndian.Uint16(nonce[:2]))
	buffer := make([]byte, 2048)
	for seq := 0; seq < 4 && ctx.Err() == nil; seq++ {
		payload := echoPacket(request, id, seq, nonce[2:])
		conn.SetDeadline(probeDeadline(ctx))
		start := time.Now()
		p.Sent++
		if _, err = conn.Write(payload); err == nil {
			for {
				n, e := conn.Read(buffer)
				if e != nil {
					break
				}
				body := buffer[:n]
				// net.IPConn normally strips IPv4 headers; tolerate platforms that retain one.
				if protocol == 1 && n >= 20 && body[0]>>4 == 4 {
					h := int(body[0]&15) * 4
					if h < 20 || h > n {
						continue
					}
					body = body[h:]
				}
				if !echoReplyMatches(body, reply, id, seq, nonce[2:]) {
					continue
				}
				p.Received++
				total += time.Since(start)
				break
			}
		}
		if seq < 3 {
			t := time.NewTimer(120 * time.Millisecond)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
	}
	p.finish(total)
	if p.Received == 0 && p.Error == "" {
		p.Error = "ICMP 未响应"
	}
	return p
}

// Only stored rule targets can be probed. Work is bounded independently of
// rule count, with no lock held while sockets wait. No business mark is applied.
func (m *Manager) ProbeForward(ctx context.Context, id string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	select {
	case diagnosticSlots <- struct{}{}:
		defer func() { <-diagnosticSlots }()
	default:
		return nil, fmt.Errorf("diagnostic capacity busy")
	}
	m.mu.Lock()
	s, exists := m.state.Rules[id]
	s = cloneSpec(s)
	m.mu.Unlock()
	if !exists || s.Deleted {
		return nil, fmt.Errorf("forward not found")
	}
	egress := EgressPolicy{}
	if s.AdvancedOptions != nil {
		egress = s.Egress
	}
	paths := []ResolvedTarget{}
	seen := map[string]bool{}
	truncated := false
	for _, p := range s.Paths() {
		if p.RetiredAt > 0 {
			continue
		}
		key := net.JoinHostPort(p.Host, fmt.Sprint(p.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(paths) == 4 {
			truncated = true
			break
		}
		paths = append(paths, p)
	}
	results := make([]map[string]any, len(paths))
	var group sync.WaitGroup
	slots := make(chan struct{}, 2)
	for i, target := range paths {
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				results[i] = map[string]any{"target": target.Host, "port": target.Port, "icmp": ProbeMetrics{PacketLoss: 100, Error: "探测超时"}, "tcp": ProbeMetrics{PacketLoss: 100, Error: "探测超时"}}
				return
			}
			var ping, tcp ProbeMetrics
			var both sync.WaitGroup
			both.Add(2)
			go func() { defer both.Done(); ping = icmpConnectivity(ctx, target.Host, egress) }()
			go func() { defer both.Done(); tcp = tcpConnectivity(ctx, target.Host, target.Port, egress) }()
			both.Wait()
			results[i] = map[string]any{"target": target.Host, "port": target.Port, "icmp": ping, "tcp": tcp}
		}()
	}
	group.Wait()
	return map[string]any{"id": id, "results": results, "truncated": truncated, "probePerformed": len(paths) > 0}, nil
}
