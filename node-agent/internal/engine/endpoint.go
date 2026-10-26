package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Endpoint has no resolver side effects. Parsing a future address family does
// not imply that this data-plane implementation can forward that family.
type Endpoint struct {
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Family string `json:"family,omitempty"`
}

func ParseEndpoint(address string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return Endpoint{}, fmt.Errorf("endpoint must be host:port (bracket IPv6): %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return Endpoint{}, fmt.Errorf("invalid endpoint port")
	}
	return (Endpoint{Host: host, Port: n}).Canonical()
}

func (e Endpoint) Canonical() (Endpoint, error) {
	if e.Port < 1 || e.Port > 65535 || e.Host == "" || strings.TrimSpace(e.Host) != e.Host {
		return e, fmt.Errorf("invalid endpoint host or port")
	}
	if ip, err := netip.ParseAddr(e.Host); err == nil {
		if ip.Zone() != "" {
			return e, fmt.Errorf("scoped IPv6 requires an interface capability")
		}
		ip = ip.Unmap()
		if e.Kind != "" && e.Kind != "ip" {
			return e, fmt.Errorf("endpoint kind does not match IP")
		}
		e.Kind = "ip"
		e.Host = ip.String()
		family := "ipv6"
		if ip.Is4() {
			family = "ipv4"
		}
		if e.Family != "" && e.Family != family {
			return e, fmt.Errorf("endpoint family mismatch")
		}
		e.Family = family
		return e, nil
	}
	if e.Kind != "" && e.Kind != "hostname" || e.Family != "" && e.Family != "auto" {
		return e, fmt.Errorf("invalid hostname kind/family")
	}
	host := strings.ToLower(strings.TrimSuffix(e.Host, "."))
	if len(host) > 253 || strings.ContainsAny(host, "[]:%/\\@?# \t\r\n") {
		return e, fmt.Errorf("invalid hostname")
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return e, fmt.Errorf("invalid DNS label")
		}
		for _, c := range label {
			if c < '0' || c > '9' {
				allNumeric = false
			}
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return e, fmt.Errorf("hostname must use ASCII/IDNA form")
			}
		}
	}
	if allNumeric {
		return e, fmt.Errorf("ambiguous numeric IP")
	}
	e.Kind = "hostname"
	e.Host = host
	e.Family = "auto"
	return e, nil
}

func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

func (s Spec) Normalize() (Spec, error) {
	if s.SchemaVersion == 3 {
		return s.normalizeAdvanced()
	}
	if s.SchemaVersion != 0 && s.SchemaVersion != 1 && s.SchemaVersion != 2 {
		return s, fmt.Errorf("unsupported ForwardSpec schema version")
	}
	if s.Deleted {
		return s, nil
	}
	if s.SchemaVersion == 2 {
		listen, err := s.Listen.Canonical()
		if err != nil {
			return s, err
		}
		target, err := s.Target.Canonical()
		if err != nil {
			return s, err
		}
		if listen.Kind != "ip" || listen.Family != "ipv4" || target.Kind != "ip" || target.Family != "ipv4" {
			return s, fmt.Errorf("unsupported capability: IPv4 direct targets only; DNS/IPv6 not enabled")
		}
		if s.ListenIP != "" && (s.ListenIP != listen.Host || s.ListenPort != listen.Port) || s.TargetIP != "" && (s.TargetIP != target.Host || s.TargetPort != target.Port) {
			return s, fmt.Errorf("conflicting legacy and structured endpoints")
		}
		s.Listen = listen
		s.Target = target
		s.ListenIP = listen.Host
		s.ListenPort = listen.Port
		s.TargetIP = target.Host
		s.TargetPort = target.Port
	}
	if len(s.Protocols) != 0 && (len(s.Protocols) != 2 || s.Protocols[0] != "tcp" || s.Protocols[1] != "udp") {
		return s, fmt.Errorf("unsupported capability: shared TCP/UDP listener required")
	}
	// Keep v1 canonical form stable for existing clients and persisted v2 state.
	s.SchemaVersion = 0
	s.Listen = Endpoint{}
	s.Target = Endpoint{}
	s.Protocols = nil
	return s, s.Validate()
}

type Capabilities struct {
	Limits           map[string]int  `json:"limits,omitempty"`
	ProtocolVersions []int           `json:"protocolVersions"`
	AgentVersion     string          `json:"agentVersion"`
	Features         map[string]bool `json:"features"`
	MaxForwards      int             `json:"maxForwards"`
	MaxBatch         int             `json:"maxBatch"`
	CounterLayer     string          `json:"counterLayer"`
}

func CurrentCapabilities() Capabilities {
	return Capabilities{ProtocolVersions: []int{1, 2, 3}, AgentVersion: "iptables-v4", Features: map[string]bool{"ipv4": true, "ipv6": true, "dns": true, "multiTarget": true, "independentProtocols": true, "shaping": true, "interfaceRouting": true, "dynamicAddresses": true, "systemMetrics": true, "runtimeStatus": true, "headerAuth": true, "sessionAuth": true, "privilegedHelper": false, "structuredEndpoint": true, "batch": true, "journalRecovery": true, "usageAcknowledgement": true, "creditLease": true, "creditPush": true, "creditPolicy": true, "icmpv4": true, "pmtuv4": true, "icmpv6": true, "pmtuv6": true, "crossFamily": false, "scopedIPv6": false}, MaxForwards: 10000, MaxBatch: 10000, CounterLayer: "network", Limits: map[string]int{"listenersPerForward": 16, "targetOriginsPerForward": 16, "targetWeightSum": 32, "retiringTargetsPerForward": 32, "resolvedPathsPerNode": 32768, "egressPoliciesPerNode": 63, "statusPage": 100, "minimumHTBGuaranteeBitsPerSecond": 8}}
}
