package engine

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func TestEchoPacketChecksumAndReplyIdentity(t *testing.T) {
	nonce := []byte("unique-test-nonce!")
	p := echoPacket(8, 123, 2, nonce)
	var sum uint32
	for i := 0; i+1 < len(p); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	if len(p)%2 != 0 {
		sum += uint32(p[len(p)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	if sum != 65535 {
		t.Fatal("invalid ICMP checksum", sum)
	}
	p[0] = 0
	if !echoReplyMatches(p, 0, 123, 2, nonce) {
		t.Fatal("valid echo rejected")
	}
	for _, change := range []func([]byte){func(p []byte) { p[0] = 8 }, func(p []byte) { p[1] = 1 }, func(p []byte) { p[4]++ }, func(p []byte) { p[6]++ }, func(p []byte) { p[8]++ }} {
		b := append([]byte{}, p...)
		change(b)
		if echoReplyMatches(b, 0, 123, 2, nonce) {
			t.Fatal("foreign echo accepted")
		}
	}
	if echoReplyMatches(p[:6], 0, 123, 2, nonce) {
		t.Fatal("short echo accepted")
	}
}

func TestProbeMetricsKeepMissingRTTAndCancelledWorkDistinct(t *testing.T) {
	p := ProbeMetrics{Sent: 4, Received: 2}
	p.finish(20 * time.Millisecond)
	if p.PacketLoss != 50 || p.AverageTime == nil || *p.AverageTime != 10 {
		t.Fatal(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p = tcpConnectivity(ctx, "127.0.0.1", 9, EgressPolicy{})
	if p.Sent != 0 || p.AverageTime != nil {
		t.Fatal("cancelled probe attempted connection", p)
	}
}
