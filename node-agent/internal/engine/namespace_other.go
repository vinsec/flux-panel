//go:build !linux

package engine

import (
	"fmt"
	"net"
)

func AcquireNamespaceLock() (net.Listener, error) {
	return nil, fmt.Errorf("kernel forwarding requires Linux")
}
