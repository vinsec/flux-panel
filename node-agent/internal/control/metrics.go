package control

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type interfaceMetric struct {
	RX     uint64   `json:"rxBytes"`
	TX     uint64   `json:"txBytes"`
	RXRate *float64 `json:"rxBytesPerSecond"`
	TXRate *float64 `json:"txBytesPerSecond"`
	Reset  bool     `json:"reset"`
}
type metricSnapshot struct {
	at          time.Time
	total, idle uint64
	interfaces  map[string]interfaceMetric
}
type metricSampler struct {
	mu   sync.Mutex
	last metricSnapshot
}

func readNumber(name string) *uint64 {
	b, e := os.ReadFile(name)
	if e != nil {
		return nil
	}
	n, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if e != nil {
		return nil
	}
	return &n
}
func (s *metricSampler) sample() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	current := metricSnapshot{at: now, interfaces: map[string]interfaceMetric{}}
	result := map[string]any{"sampledAt": now.UnixMilli(), "cpu_usage": nil, "memory_usage": nil, "network": current.interfaces}
	if data, e := os.ReadFile("/proc/stat"); e == nil {
		f := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
		if len(f) >= 9 && f[0] == "cpu" {
			for i := 1; i <= 8; i++ {
				n, _ := strconv.ParseUint(f[i], 10, 64)
				current.total += n
				if i == 4 || i == 5 {
					current.idle += n
				}
			}
			if s.last.total > 0 && current.total > s.last.total && current.idle >= s.last.idle {
				busy := float64(current.total-s.last.total-(current.idle-s.last.idle)) / float64(current.total-s.last.total) * 100
				result["cpu_usage"] = busy
			}
		}
	}
	if data, e := os.ReadFile("/proc/meminfo"); e == nil {
		values := map[string]uint64{}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				values[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
		if total := values["MemTotal"]; total > 0 {
			available, ok := values["MemAvailable"]
			if ok && available <= total {
				result["memory_usage"] = float64(total-available) / float64(total) * 100
				result["memoryTotalBytes"] = total * 1024
				result["memoryAvailableBytes"] = available * 1024
			}
		}
	}
	seconds := now.Sub(s.last.at).Seconds()
	result["intervalSeconds"] = nil
	if !s.last.at.IsZero() {
		result["intervalSeconds"] = seconds
	}
	if data, e := os.ReadFile("/proc/net/dev"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			f := strings.Fields(parts[1])
			if len(f) < 16 {
				continue
			}
			rx, e1 := strconv.ParseUint(f[0], 10, 64)
			tx, e2 := strconv.ParseUint(f[8], 10, 64)
			if e1 != nil || e2 != nil {
				continue
			}
			name := strings.TrimSpace(parts[0])
			metric := interfaceMetric{RX: rx, TX: tx}
			if old, exists := s.last.interfaces[name]; exists && seconds > 0 {
				if rx >= old.RX && tx >= old.TX {
					rxRate := float64(rx-old.RX) / seconds
					txRate := float64(tx-old.TX) / seconds
					metric.RXRate = &rxRate
					metric.TXRate = &txRate
				} else {
					metric.Reset = true
				}
			}
			current.interfaces[name] = metric
		}
	}
	result["conntrackCount"] = readNumber("/proc/sys/net/netfilter/nf_conntrack_count")
	result["conntrackMax"] = readNumber("/proc/sys/net/netfilter/nf_conntrack_max")
	if data, e := os.ReadFile("/proc/uptime"); e == nil {
		f := strings.Fields(string(data))
		if len(f) > 0 {
			if n, e := strconv.ParseFloat(f[0], 64); e == nil {
				result["uptimeSeconds"] = n
			}
		}
	}
	s.last = current
	return result
}
