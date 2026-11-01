package engine

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Schema 3 keeps desired endpoints distinct from node-resolved runtime paths.
// Runtime is supplied by the node, never accepted from a control request.
type AdvancedOptions struct {
	ProtocolFilter *ProtocolFilter `json:"protocolFilter,omitempty"`
	Listeners      []Listener      `json:"listeners,omitempty"`
	Targets        []Target        `json:"targets,omitempty"`
	Selection      string          `json:"selection,omitempty"`
	DNS            DNSPolicy       `json:"dnsPolicy,omitempty"`
	Health         HealthPolicy    `json:"health,omitempty"`
	Egress         EgressPolicy    `json:"egress,omitempty"`
	Bandwidth      BandwidthPolicy `json:"bandwidth,omitempty"`
	Traffic        *TrafficPolicy  `json:"traffic,omitempty"`
	Runtime        ResolutionState `json:"runtime,omitempty"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Family   string `json:"family,omitempty"`
}
type Target struct {
	Endpoint Endpoint `json:"endpoint"`
	Weight   int      `json:"weight"`
}
type DNSPolicy struct {
	FailClosed  bool  `json:"failClosed,omitempty"`
	StaleMillis int64 `json:"staleMillis,omitempty"`
	DrainMillis int64 `json:"drainMillis,omitempty"`
}
type HealthPolicy struct {
	Protocol       string `json:"protocol,omitempty"`
	Port           int    `json:"port,omitempty"`
	IntervalMillis int64  `json:"intervalMillis,omitempty"`
	TimeoutMillis  int64  `json:"timeoutMillis,omitempty"`
	Rise           int    `json:"rise,omitempty"`
	Fall           int    `json:"fall,omitempty"`
	Payload        string `json:"payload,omitempty"`
	Expected       string `json:"expected,omitempty"`
}
type EgressPolicy struct {
	Interface   string `json:"interface,omitempty"`
	SourceIPv4  string `json:"sourceIPv4,omitempty"`
	SourceIPv6  string `json:"sourceIPv6,omitempty"`
	GatewayIPv4 string `json:"gatewayIPv4,omitempty"`
	GatewayIPv6 string `json:"gatewayIPv6,omitempty"`
}
type BandwidthGroup struct {
	ID                string `json:"id,omitempty"`
	UpBitsPerSecond   uint64 `json:"upBitsPerSecond,omitempty"`
	DownBitsPerSecond uint64 `json:"downBitsPerSecond,omitempty"`
}
type BandwidthPolicy struct {
	UpBitsPerSecond   uint64         `json:"upBitsPerSecond,omitempty"`
	DownBitsPerSecond uint64         `json:"downBitsPerSecond,omitempty"`
	User              BandwidthGroup `json:"user,omitempty"`
	Tunnel            BandwidthGroup `json:"tunnel,omitempty"`
}
type ResolvedTarget struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Family      string `json:"family"`
	Origin      string `json:"origin"`
	Weight      int    `json:"weight"`
	Healthy     bool   `json:"healthy"`
	Successes   int    `json:"successes,omitempty"`
	Failures    int    `json:"failures,omitempty"`
	NextProbeAt int64  `json:"nextProbeAt,omitempty"`
	RetiredAt   int64  `json:"retiredAt,omitempty"`
	FreshUntil  int64  `json:"freshUntil,omitempty"`
	AcceptNew   bool   `json:"acceptNew"`
}
type ResolutionState struct {
	EgressGroup   uint8            `json:"-"`
	Generation    uint64           `json:"generation,omitempty"`
	ResolvedAt    int64            `json:"resolvedAt,omitempty"`
	NextResolveAt int64            `json:"nextResolveAt,omitempty"`
	Status        string           `json:"status,omitempty"`
	Error         string           `json:"error,omitempty"`
	Targets       []ResolvedTarget `json:"targets,omitempty"`
}

// TrafficPolicy changes hook coverage and NAT semantics, so requires schema 4.
// ReturnPathConfirmed is an operator assertion about the target's routing; the
// agent cannot prove a remote host's return route from a local route lookup.
type TrafficPolicy struct {
	LocalOutput         bool   `json:"localOutput,omitempty"`
	LocalTargets        bool   `json:"localTargets,omitempty"`
	SourceMode          string `json:"sourceMode,omitempty"`
	ReturnPathConfirmed bool   `json:"returnPathConfirmed,omitempty"`
}

func (s Spec) Advanced() bool {
	return s.SchemaVersion == 3 || s.SchemaVersion == 4 || s.SchemaVersion == 5
}
func (s Spec) trafficPolicy() TrafficPolicy {
	if s.AdvancedOptions != nil && s.Traffic != nil {
		return *s.Traffic
	}
	return TrafficPolicy{}
}
func (s Spec) needsTrafficSets() bool { return s.localTraffic() || s.preserveSource() }
func (s Spec) localTraffic() bool {
	return s.AdvancedOptions != nil && (s.trafficPolicy().LocalOutput || s.trafficPolicy().LocalTargets)
}
func (s Spec) preserveSource() bool {
	return s.AdvancedOptions != nil && s.trafficPolicy().SourceMode == "preserve"
}
func requiredStateFormat(rules map[string]Spec) int {
	version := 3
	for _, s := range rules {
		if s.SchemaVersion == 5 {
			return 7
		}
		if s.SchemaVersion == 4 {
			version = 5
			continue
		}
		if s.Advanced() && version < 4 {
			version = 4
		}
	}
	return version
}
func (l Listener) Key() string {
	return l.Family + "/" + l.Protocol + "/" + (Endpoint{Host: l.Host, Port: l.Port}).String()
}
func (r ResolvedTarget) Key() string { return (Endpoint{Host: r.Host, Port: r.Port}).String() }
func (b BandwidthPolicy) Enabled() bool {
	return b.UpBitsPerSecond+b.DownBitsPerSecond+b.User.UpBitsPerSecond+b.User.DownBitsPerSecond+b.Tunnel.UpBitsPerSecond+b.Tunnel.DownBitsPerSecond > 0
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var groupID = regexp.MustCompile(`^[a-zA-Z0-9_:-]{1,64}$`)

func (s Spec) normalizeAdvanced() (Spec, error) {
	if s.AdvancedOptions != nil {
		if e := validateProtocolPolicy(s); e != nil {
			return s, e
		}
	}
	if s.AdvancedOptions == nil {
		s.AdvancedOptions = &AdvancedOptions{}
	} else {
		copy := *s.AdvancedOptions
		if s.ProtocolFilter != nil {
			policy := *s.ProtocolFilter
			copy.ProtocolFilter = &policy
		}
		if s.Traffic != nil {
			policy := *s.Traffic
			copy.Traffic = &policy
		}
		copy.Listeners = slices.Clone(copy.Listeners)
		copy.Targets = slices.Clone(copy.Targets)
		copy.Runtime.Targets = slices.Clone(copy.Runtime.Targets)
		s.AdvancedOptions = &copy
	}
	if !serviceID.MatchString(s.ID) || len(s.ID) > 100 || s.Revision < 1 {
		return s, fmt.Errorf("invalid service id or revision")
	}
	if s.Deleted {
		return s, nil
	}
	if len(s.Listeners) == 0 {
		listen := s.Listen
		if listen.Host == "" {
			listen = Endpoint{Host: s.ListenIP, Port: s.ListenPort}
		}
		protocols := s.Protocols
		if len(protocols) == 0 {
			protocols = []string{"tcp", "udp"}
		}
		hosts := []string{listen.Host}
		if listen.Family == "dual" {
			if listen.Host != "::" {
				return s, fmt.Errorf("dual listener must use ::")
			}
			hosts = []string{"0.0.0.0", "::"}
		}
		for _, host := range hosts {
			for _, protocol := range protocols {
				s.Listeners = append(s.Listeners, Listener{Host: host, Port: listen.Port, Protocol: protocol})
			}
		}
	}
	if len(s.Listeners) > 16 {
		return s, fmt.Errorf("at most 16 listeners per forwarding")
	}
	seen := map[string]bool{}
	protocols := []string{}
	for i, l := range s.Listeners {
		if l.Protocol != "tcp" && l.Protocol != "udp" {
			return s, fmt.Errorf("listener protocol must be tcp or udp")
		}
		e, err := (Endpoint{Kind: "ip", Host: l.Host, Port: l.Port, Family: l.Family}).Canonical()
		if err != nil {
			return s, err
		}
		ip := netip.MustParseAddr(e.Host)
		if ip.IsLoopback() && !s.trafficPolicy().LocalOutput || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return s, fmt.Errorf("listener must be an external unicast or wildcard address")
		}
		l.Host = e.Host
		l.Family = e.Family
		s.Listeners[i] = l
		if seen[l.Key()] {
			return s, fmt.Errorf("duplicate listener")
		}
		seen[l.Key()] = true
		if !slices.Contains(protocols, l.Protocol) {
			protocols = append(protocols, l.Protocol)
		}
	}
	slices.SortFunc(s.Listeners, func(a, b Listener) int { return strings.Compare(a.Key(), b.Key()) })
	slices.Sort(protocols)
	s.Protocols = protocols
	if len(s.Targets) == 0 {
		t := s.Target
		if t.Host == "" {
			t = Endpoint{Host: s.TargetIP, Port: s.TargetPort}
		}
		s.Targets = []Target{{Endpoint: t, Weight: 1}}
	}
	if len(s.Targets) > 16 {
		return s, fmt.Errorf("at most 16 target origins per forwarding")
	}
	seen = map[string]bool{}
	weight := 0
	for i, t := range s.Targets {
		e, err := t.Endpoint.Canonical()
		if err != nil {
			return s, err
		}
		if e.Kind == "ip" {
			ip := netip.MustParseAddr(e.Host)
			if ip.IsUnspecified() || ip.IsLoopback() && !s.trafficPolicy().LocalTargets || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("255.255.255.255") {
				return s, fmt.Errorf("target must be external unicast; scoped/link-local targets are not enabled")
			}
		}
		if seen[e.String()] {
			return s, fmt.Errorf("duplicate target origin")
		}
		seen[e.String()] = true
		if t.Weight == 0 {
			t.Weight = 1
		}
		if t.Weight < 1 || t.Weight > 32 {
			return s, fmt.Errorf("target weight must be 1..32")
		}
		weight += t.Weight
		t.Endpoint = e
		s.Targets[i] = t
	}
	if weight > 32 {
		return s, fmt.Errorf("sum of target weights must not exceed 32")
	}
	if s.Selection == "" {
		s.Selection = "fifo"
	}
	if !slices.Contains([]string{"fifo", "hash", "round", "random"}, s.Selection) {
		return s, fmt.Errorf("unsupported target selection")
	}
	if s.DNS.StaleMillis == 0 && !s.DNS.FailClosed {
		s.DNS.StaleMillis = 30000
	}
	if s.DNS.DrainMillis == 0 {
		s.DNS.DrainMillis = 300000
	}
	if s.DNS.StaleMillis < 0 || s.DNS.StaleMillis > 300000 || s.DNS.DrainMillis < 1000 || s.DNS.DrainMillis > 3600000 {
		return s, fmt.Errorf("invalid DNS grace or drain bound")
	}
	if s.Health.Protocol != "" {
		if s.Health.Protocol != "tcp" && s.Health.Protocol != "udp" {
			return s, fmt.Errorf("health protocol must be tcp or explicit UDP exchange")
		}
		if s.Health.IntervalMillis == 0 {
			s.Health.IntervalMillis = 5000
		}
		if s.Health.TimeoutMillis == 0 {
			s.Health.TimeoutMillis = 500
		}
		if s.Health.Rise == 0 {
			s.Health.Rise = 2
		}
		if s.Health.Fall == 0 {
			s.Health.Fall = 2
		}
		if s.Health.IntervalMillis < 1000 || s.Health.IntervalMillis > 60000 || s.Health.TimeoutMillis < 50 || s.Health.TimeoutMillis > 3000 || s.Health.Rise < 1 || s.Health.Rise > 10 || s.Health.Fall < 1 || s.Health.Fall > 10 || s.Health.Port < 0 || s.Health.Port > 65535 {
			return s, fmt.Errorf("invalid health probe bounds")
		}
		if s.Health.Protocol == "udp" {
			for _, v := range []string{s.Health.Payload, s.Health.Expected} {
				b, e := base64.StdEncoding.DecodeString(v)
				if e != nil || len(b) == 0 || len(b) > 64 {
					return s, fmt.Errorf("UDP health exchange requires 1..64 byte base64 payload and expected response")
				}
			}
		}
	}
	if s.Egress.Interface != "" && !interfaceName.MatchString(s.Egress.Interface) {
		return s, fmt.Errorf("invalid egress interface")
	}
	for _, entry := range []struct {
		v    string
		four bool
	}{{s.Egress.SourceIPv4, true}, {s.Egress.GatewayIPv4, true}, {s.Egress.SourceIPv6, false}, {s.Egress.GatewayIPv6, false}} {
		if entry.v == "" {
			continue
		}
		a, e := netip.ParseAddr(entry.v)
		if e != nil || a.Zone() != "" || a.Is4() != entry.four || a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() {
			return s, fmt.Errorf("invalid egress source or gateway")
		}
		if s.Egress.Interface == "" {
			return s, fmt.Errorf("egress source/gateway requires an explicit interface")
		}
	}
	for _, rate := range []uint64{s.Bandwidth.UpBitsPerSecond, s.Bandwidth.DownBitsPerSecond, s.Bandwidth.User.UpBitsPerSecond, s.Bandwidth.User.DownBitsPerSecond, s.Bandwidth.Tunnel.UpBitsPerSecond, s.Bandwidth.Tunnel.DownBitsPerSecond} {
		if rate != 0 && (rate < 1000 || rate > 1000000000000) {
			return s, fmt.Errorf("bandwidth rates must be 1000..1e12 bits/second or zero")
		}
	}
	for _, g := range []BandwidthGroup{s.Bandwidth.User, s.Bandwidth.Tunnel} {
		if (g.UpBitsPerSecond > 0 || g.DownBitsPerSecond > 0) && !groupID.MatchString(g.ID) {
			return s, fmt.Errorf("bandwidth group requires a bounded identifier")
		}
	}
	s.Listen = Endpoint{Kind: "ip", Host: s.Listeners[0].Host, Port: s.Listeners[0].Port, Family: s.Listeners[0].Family}
	s.ListenIP = s.Listen.Host
	s.ListenPort = s.Listen.Port
	s.Target = s.Targets[0].Endpoint
	s.TargetIP = s.Target.Host
	s.TargetPort = s.Target.Port
	return s, s.validateAdvanced()
}
func (s Spec) validateAdvanced() error {
	if s.IntentHash != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s.IntentHash) {
		return fmt.Errorf("invalid desired intent hash")
	}
	if s.AdvancedOptions == nil {
		return fmt.Errorf("missing advanced options")
	}
	if s.SchemaVersion < 4 && s.trafficPolicy() != (TrafficPolicy{}) {
		return fmt.Errorf("traffic options require ForwardSpec schema 4")
	}
	if s.trafficPolicy().SourceMode != "" && s.trafficPolicy().SourceMode != "masquerade" && s.trafficPolicy().SourceMode != "preserve" {
		return fmt.Errorf("source mode must be masquerade or preserve")
	}
	if s.preserveSource() && !s.trafficPolicy().ReturnPathConfirmed {
		return fmt.Errorf("preserving source requires confirmed return routing through this node")
	}
	if !s.preserveSource() && s.trafficPolicy().ReturnPathConfirmed {
		return fmt.Errorf("return routing confirmation requires preserve mode")
	}
	if s.preserveSource() && (s.Egress.SourceIPv4 != "" || s.Egress.SourceIPv6 != "") {
		return fmt.Errorf("source preservation conflicts with explicit SNAT")
	}
	// Local shaping prerequisites are checked operationally by the kernel.
	// Reconciliation must retain new desired limits and close unprepared rules,
	// rather than keeping the preceding unlimited generation active.
	if len(s.Listeners) == 0 || len(s.Targets) == 0 {
		return fmt.Errorf("advanced spec requires listeners and targets")
	}
	for _, t := range s.Targets {
		if t.Endpoint.Kind == "ip" {
			if err := s.validateLocalTargetOptions(t.Endpoint.Host, t.Endpoint.Family); err != nil {
				return err
			}
		}
	}
	for _, l := range s.Listeners {
		for _, t := range s.Targets {
			if t.Endpoint.Kind == "ip" && l.Host == t.Endpoint.Host && l.Port == t.Endpoint.Port {
				return fmt.Errorf("forwarding loop")
			}
		}
	}
	return nil
}

func (s Spec) Paths() []ResolvedTarget {
	if !s.Advanced() {
		if s.Deleted {
			return nil
		}
		return []ResolvedTarget{{Host: s.TargetIP, Port: s.TargetPort, Family: "ipv4", Weight: 1, Healthy: true, AcceptNew: true}}
	}
	if s.AdvancedOptions == nil {
		return nil
	}
	return s.Runtime.Targets
}
func (s Spec) TargetKeys() []string {
	out := []string{}
	for _, p := range s.Paths() {
		out = append(out, fmt.Sprintf("%s,0x%x", p.Host, flowMark(s)))
	}
	return out
}
func (s Spec) ListenerList() []Listener {
	if s.Advanced() {
		return s.Listeners
	}
	return []Listener{{Protocol: "tcp", Host: s.ListenIP, Port: s.ListenPort, Family: "ipv4"}, {Protocol: "udp", Host: s.ListenIP, Port: s.ListenPort, Family: "ipv4"}}
}

func desiredSpecDigest(s Spec) string {
	s.IntentHash = ""
	if s.AdvancedOptions != nil {
		options := *s.AdvancedOptions
		options.Runtime = ResolutionState{}
		s.AdvancedOptions = &options
	}
	s.Token = 0
	s.Revision = 0
	return digest(s)
}
func desiredNetworkDigest(s Spec) string {
	if !s.Advanced() {
		return digest([]any{s.ListenIP, s.ListenPort, s.TargetIP, s.TargetPort})
	}
	return digest([]any{s.SchemaVersion, s.Listeners, s.Targets, s.Selection, s.Egress, s.Traffic, s.ProtocolFilter})
}
func allNumericTargets(s Spec) bool {
	for _, t := range s.Targets {
		if t.Endpoint.Kind != "ip" {
			return false
		}
	}
	return true
}

func resolutionIntentDigest(s Spec) string {
	s.Enabled = false
	s.Deleted = false
	s.ExpiresAt = 0
	s.LeaseRequired = false
	if s.AdvancedOptions != nil {
		options := *s.AdvancedOptions
		options.Bandwidth = BandwidthPolicy{}
		s.AdvancedOptions = &options
	}
	return desiredSpecDigest(s)
}

// Preserving a local UDP client's source requires service-side fixed reply
// binding/IP_PKTINFO. Without that contract, default local INPUT SNAT is needed.
func (s Spec) validateLocalTargetOptions(host, family string) error {
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return nil
	}
	if ip.Is6() {
		for _, l := range s.Listeners {
			if l.Family == family && !netip.MustParseAddr(l.Host).IsLoopback() {
				return fmt.Errorf("external IPv6 loopback targets are not supported; use an assigned local address")
			}
		}
	}

	return nil
}
