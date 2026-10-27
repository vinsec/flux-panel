package engine

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type udpBindings struct {
	exact    map[string]bool
	wildcard map[string]bool
	err      error
}

var udpBindingCache struct {
	sync.Mutex
	at        time.Time
	namespace string
	value     udpBindings
}

func udpBindingKey(family, host string, port int) string {
	return fmt.Sprintf("%s/%s/%d", family, host, port)
}
func parseUDPBindings(family, text string, out *udpBindings) error {
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !strings.Contains(fields[0], ":") {
			continue
		}
		pair := strings.Split(fields[1], ":")
		if len(pair) != 2 {
			continue
		}
		raw, err := hex.DecodeString(pair[0])
		if err != nil || len(raw) != 4 && len(raw) != 16 {
			continue
		}
		for n := 0; n < len(raw); n += 4 {
			raw[n], raw[n+3] = raw[n+3], raw[n]
			raw[n+1], raw[n+2] = raw[n+2], raw[n+1]
		}
		ip, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(pair[1], 16, 16)
		if err != nil {
			continue
		}
		if ip.IsUnspecified() {
			out.wildcard[fmt.Sprintf("%s/%d", family, port)] = true
		} else {
			out.exact[udpBindingKey(family, ip.String(), int(port))] = true
		}
	}
	return scanner.Err()
}
func readUDPBindings() udpBindings {
	namespace, _ := os.Readlink("/proc/self/ns/net")
	udpBindingCache.Lock()
	defer udpBindingCache.Unlock()
	if namespace == udpBindingCache.namespace && time.Since(udpBindingCache.at) < 100*time.Millisecond {
		return udpBindingCache.value
	}
	out := udpBindings{exact: map[string]bool{}, wildcard: map[string]bool{}}
	for _, f := range []struct{ family, path string }{{"ipv4", "/proc/net/udp"}, {"ipv6", "/proc/net/udp6"}} {
		data, err := os.ReadFile(f.path)
		if os.IsNotExist(err) && f.family == "ipv6" {
			continue
		}
		if err != nil {
			out.err = err
			break
		}
		if err = parseUDPBindings(f.family, string(data), &out); err != nil {
			out.err = err
			break
		}
	}
	udpBindingCache.namespace = namespace
	udpBindingCache.at = time.Now()
	udpBindingCache.value = out
	return out
}
func localUDPSourceProblem(target ResolvedTarget) string {
	b := readUDPBindings()
	if b.err != nil {
		return "cannot inspect local UDP reply-source binding"
	}
	if !b.exact[udpBindingKey(target.Family, target.Host, target.Port)] {
		return "UDP source preservation requires a service bound to the exact target address; wildcard/IP_PKTINFO contracts are not inferred"
	}
	if b.wildcard[fmt.Sprintf("%s/%d", target.Family, target.Port)] || target.Family == "ipv4" && b.wildcard[fmt.Sprintf("ipv6/%d", target.Port)] {
		return "UDP reply-source binding is ambiguous because a wildcard socket shares the target port"
	}
	return ""
}
