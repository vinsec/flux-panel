package engine

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

type Spec struct {
	Token      uint32 `json:"token,omitempty"`
	ID         string `json:"id"`
	Revision   int64  `json:"revision"`
	ListenIP   string `json:"listenIP"`
	ListenPort int    `json:"listenPort"`
	TargetIP   string `json:"targetIP"`
	TargetPort int    `json:"targetPort"`
	Enabled    bool   `json:"enabled"`
	Deleted    bool   `json:"deleted,omitempty"`
	ExpiresAt  int64  `json:"expiresAt,omitempty"`
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
	Epoch    string  `json:"epoch"`
	Sequence int64   `json:"sequence"`
	Usage    []Usage `json:"usage"`
}
type State struct {
	FormatVersion int               `json:"formatVersion,omitempty"`
	NextToken     uint32            `json:"nextToken,omitempty"`
	Epoch         string            `json:"epoch"`
	Sequence      int64             `json:"sequence"`
	Rules         map[string]Spec   `json:"rules"`
	Totals        map[string]Usage  `json:"totals"`
	Last          map[string]uint64 `json:"last"`
}
