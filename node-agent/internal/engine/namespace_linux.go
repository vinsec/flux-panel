//go:build linux

package engine

import (
	"fmt"
	"net"
)

// Abstract AF_UNIX names belong to the network namespace, including across
// containers with different mount namespaces. A path lock alone cannot do this.
func AcquireNamespaceLock() (net.Listener, error) {
	// Retain the old abstract lock name to exclude all prior Flux releases.
	l, e := net.Listen("unix", "@flux-iptables-manager-v3")
	if e != nil {
		return nil, fmt.Errorf("network namespace is already managed by another agent: %w", e)
	}
	return l, nil
}
