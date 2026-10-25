package engine

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

type Spec struct {
	SchemaVersion int      `json:"schemaVersion,omitempty"`
	Listen        Endpoint `json:"listen,omitempty"`
	Target        Endpoint `json:"target,omitempty"`
	Protocols     []string `json:"protocols,omitempty"`
	Token         uint32   `json:"token,omitempty"`
	ID            string   `json:"id"`
	Revision      int64    `json:"revision"`
	ListenIP      string   `json:"listenIP"`
	ListenPort    int      `json:"listenPort"`
	TargetIP      string   `json:"targetIP"`
	TargetPort    int      `json:"targetPort"`
	Enabled       bool     `json:"enabled"`
	Deleted       bool     `json:"deleted,omitempty"`
	ExpiresAt     int64    `json:"expiresAt,omitempty"`
	LeaseRequired bool     `json:"leaseRequired,omitempty"`
}

var serviceID = regexp.MustCompile(`^[0-9]+_[0-9]+_[0-9]+$`)

func (s Spec) Validate() error {
	if !serviceID.MatchString(s.ID) || len(s.ID) > 100 || s.Revision < 1 {
		return fmt.Errorf("invalid service id or revision")
	}
	if s.Deleted {
		return nil
	}
	ip, target := net.ParseIP(s.ListenIP), net.ParseIP(s.TargetIP)
	if ip == nil || ip.To4() == nil || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || target == nil || target.To4() == nil || target.IsUnspecified() || target.IsLoopback() || target.IsMulticast() || target.Equal(net.IPv4bcast) {
		return fmt.Errorf("only explicit IPv4 listener and unicast IPv4 target are supported")
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 || s.TargetPort < 1 || s.TargetPort > 65535 {
		return fmt.Errorf("invalid port")
	}
	if ip.Equal(target) && s.ListenPort == s.TargetPort {
		return fmt.Errorf("forwarding loop")
	}
	return nil
}

func (s Spec) Active() bool {
	return !s.Deleted && s.Enabled && (s.ExpiresAt == 0 || time.Now().UnixMilli() < s.ExpiresAt)
}

type Usage struct {
	ID   string `json:"id"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}
type Report struct {
	CreditMode   bool               `json:"creditMode"`
	Counters     []CounterWatermark `json:"counters,omitempty"`
	BootID       string             `json:"bootId"`
	Epoch        string             `json:"epoch"`
	Sequence     int64              `json:"sequence"`
	Usage        []Usage            `json:"usage"`
	Generation   uint64             `json:"generation"`
	CheckpointAt int64              `json:"checkpointAt"`
	Recovery     RecoveryInfo       `json:"recovery"`
	Leases       []LeaseUsage       `json:"leases,omitempty"`
	Requests     []string           `json:"requests,omitempty"`
}
type RecoveryInfo struct {
	PossibleLoss  bool   `json:"possibleLoss"`
	LastDurableAt int64  `json:"lastDurableAt"`
	Reason        string `json:"reason,omitempty"`
}
type State struct {
	ReportCursor       string            `json:"reportCursor,omitempty"`
	StrictCredit       bool              `json:"strictCredit,omitempty"`
	AccountingBlocked  bool              `json:"accountingBlocked,omitempty"`
	MaintenanceBootID  string            `json:"maintenanceBootId,omitempty"`
	LastAckAt          int64             `json:"lastAckAt"`
	LastConnectedAt    int64             `json:"lastConnectedAt"`
	KernelID           string            `json:"kernelId,omitempty"`
	Quarantine         map[uint32]int64  `json:"quarantine,omitempty"`
	MaintenancePending bool              `json:"maintenancePending,omitempty"`
	LeaseAcks          map[string]uint64 `json:"leaseAcks,omitempty"`
	AckCounters        map[string]uint64 `json:"ackCounters,omitempty"`
	CounterRetiredAt   map[string]int64  `json:"counterRetiredAt,omitempty"`
	ClosedLeaseAcks    map[string]bool   `json:"closedLeaseAcks,omitempty"`
	FormatVersion      int               `json:"formatVersion,omitempty"`
	NextToken          uint32            `json:"nextToken,omitempty"`
	Epoch              string            `json:"epoch"`
	Sequence           int64             `json:"sequence"`
	Rules              map[string]Spec   `json:"rules"`
	Totals             map[string]Usage  `json:"totals"`
	Last               map[string]uint64 `json:"last"`
	CommitID           string            `json:"commitId,omitempty"`
	Generation         uint64            `json:"generation"`
	Ack                map[string]Usage  `json:"ack,omitempty"`
	AckSequence        int64             `json:"ackSequence"`
	Floors             map[string]int64  `json:"revisionFloors,omitempty"`
	FreeTokens         []uint32          `json:"freeTokens,omitempty"`
	RetiredAt          map[string]int64  `json:"retiredAt,omitempty"`
	Leases             map[string]Lease  `json:"leases,omitempty"`
	RequestTimes       map[int64]int64   `json:"requestTimes,omitempty"`
	Receipts           []Receipt         `json:"receipts,omitempty"`
	BootID             string            `json:"bootId,omitempty"`
	LastDurableAt      int64             `json:"lastDurableAt"`
	Recovery           RecoveryInfo      `json:"recovery"`
}
