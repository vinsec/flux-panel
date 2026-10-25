// A constant echo endpoint / latency observer, separate from both forwarders.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	role := flag.String("role", "client", "server or client")
	host := flag.String("host", "10.204.1.1", "numeric private target")
	port := flag.Int("port", 18001, "port")
	protocol := flag.String("protocol", "tcp", "tcp or udp")
	fresh := flag.Bool("fresh", false, "new TCP connection per sample")
	samples := flag.Int("samples", 500, "sample count")
	pace := flag.Int("pace-us", 1000, "delay between samples")
	bulk := flag.Int64("bulk-bytes", 0, "exact bytes with receiver acknowledgement")
	parallel := flag.Int("parallel", 1, "bulk streams")
	reverse := flag.Bool("reverse", false, "bulk download")
	flag.Parse()
	if *role == "server" {
		go serveBulk(*port + 1)
		serve(*port)
		return
	}
	ip := net.ParseIP(*host)
	if ip == nil || !ip.IsPrivate() {
		panic("latency target must be a private numeric IP")
	}
	addr := net.JoinHostPort(*host, fmt.Sprint(*port))
	if *bulk > 0 {
		bulkClient(addr, *bulk, *parallel, *reverse)
		return
	}
	payload := make([]byte, 64)
	received := make([]byte, 64)
	values := []float64{}
	loss := 0
	var c net.Conn
	var e error
	dial := func() (net.Conn, error) {
		c, e := net.DialTimeout(*protocol, addr, 2*time.Second)
		if t, ok := c.(*net.TCPConn); ok {
			t.SetNoDelay(true)
		}
		return c, e
	}
	if !*fresh {
		c, e = dial()
		if e != nil {
			panic(e)
		}
		defer c.Close()
	}
	for i := -20; i < *samples; i++ {
		time.Sleep(time.Duration(*pace) * time.Microsecond)
		binary.BigEndian.PutUint64(payload, uint64(i+20))
		start := time.Now()
		if *fresh {
			c, e = dial()
			if e != nil {
				if i >= 0 {
					loss++
				}
				continue
			}
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_, e = c.Write(payload)
		if e == nil {
			_, e = io.ReadFull(c, received)
		}
		elapsed := float64(time.Since(start).Nanoseconds()) / 1000
		if *fresh {
			c.Close()
		}
		if e != nil {
			if i >= 0 {
				loss++
			}
			continue
		}
		if binary.BigEndian.Uint64(received) != uint64(i+20) {
			panic("echo mismatch")
		}
		if i >= 0 {
			values = append(values, elapsed)
		}
	}
	sort.Float64s(values)
	pct := func(p float64) float64 {
		if len(values) == 0 {
			return 0
		}
		return values[int(float64(len(values)-1)*p)]
	}
	json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"samples": len(values), "lost": loss, "p50_us": pct(.5), "p95_us": pct(.95), "p99_us": pct(.99), "max_us": pct(1), "values_us": values})
}

func transfer(c net.Conn, n int64, write bool) error {
	b := make([]byte, 65536)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	for n > 0 {
		k := int64(len(b))
		if n < k {
			k = n
		}
		var e error
		if write {
			offset := 0
			for offset < int(k) {
				var written int
				written, e = c.Write(b[offset:k])
				offset += written
				if e != nil {
					break
				}
			}
		} else {
			_, e = io.ReadFull(c, b[:k])
		}
		if e != nil {
			return e
		}
		n -= k
	}
	return nil
}
func serveBulk(port int) {
	ln, e := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", fmt.Sprint(port)))
	if e != nil {
		panic(e)
	}
	for {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(20 * time.Second))
			h := make([]byte, 9)
			if _, e := io.ReadFull(c, h); e != nil {
				return
			}
			n := int64(binary.BigEndian.Uint64(h[1:]))
			if n < 1 || n > 256*1024*1024 {
				return
			}
			c.Write([]byte{1})
			goByte := make([]byte, 1)
			if _, e := io.ReadFull(c, goByte); e != nil {
				return
			}
			if e := transfer(c, n, h[0] == 1); e != nil {
				return
			}
			ack := make([]byte, 8)
			binary.BigEndian.PutUint64(ack, uint64(n))
			if h[0] == 1 {
				if _, e := io.ReadFull(c, ack); e != nil {
					return
				}
				if binary.BigEndian.Uint64(ack) != uint64(n) {
					return
				}
			}
			c.Write(ack)
		}(c)
	}
}
func bulkClient(addr string, total int64, parallel int, reverse bool) {
	if parallel < 1 || parallel > 8 || total%int64(parallel) != 0 {
		panic("invalid bulk size/parallel")
	}
	n := total / int64(parallel)
	conns := make([]net.Conn, parallel)
	for i := range conns {
		c, e := net.DialTimeout("tcp4", addr, 2*time.Second)
		if e != nil {
			panic(e)
		}
		conns[i] = c
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		h := make([]byte, 9)
		if reverse {
			h[0] = 1
		}
		binary.BigEndian.PutUint64(h[1:], uint64(n))
		c.Write(h)
		ready := make([]byte, 1)
		if _, e = io.ReadFull(c, ready); e != nil || ready[0] != 1 {
			panic("bulk peer not ready")
		}
	}
	start := make(chan struct{})
	errors := make(chan error, parallel)
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			<-start
			c.Write([]byte{1})
			if e := transfer(c, n, !reverse); e != nil {
				errors <- e
				return
			}
			ack := make([]byte, 8)
			binary.BigEndian.PutUint64(ack, uint64(n))
			if reverse {
				c.Write(ack)
			}
			if _, e := io.ReadFull(c, ack); e != nil {
				errors <- e
				return
			}
			if binary.BigEndian.Uint64(ack) != uint64(n) {
				errors <- fmt.Errorf("receiver byte count mismatch")
			}
		}(c)
	}
	t := time.Now()
	close(start)
	wg.Wait()
	seconds := time.Since(t).Seconds()
	close(errors)
	for e := range errors {
		panic(e)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"bytes": total, "seconds": seconds, "bits_per_second": float64(total) * 8 / seconds, "parallel": parallel, "reverse": reverse, "receiver_acknowledged": true})
}
func serve(port int) {
	addr := net.JoinHostPort("0.0.0.0", fmt.Sprint(port))
	ln, e := net.Listen("tcp4", addr)
	if e != nil {
		panic(e)
	}
	udp, e := net.ListenPacket("udp4", addr)
	if e != nil {
		panic(e)
	}
	go func() {
		b := make([]byte, 65536)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	for {
		c, e := ln.Accept()
		if e != nil {
			panic(e)
		}
		if t, ok := c.(*net.TCPConn); ok {
			t.SetNoDelay(true)
		}
		go func(c net.Conn) {
			defer c.Close()
			b := make([]byte, 65536)
			for {
				n, e := c.Read(b)
				if n > 0 {
					if _, w := c.Write(b[:n]); w != nil {
						return
					}
				}
				if e != nil {
					return
				}
			}
		}(c)
	}
}
