//go:build !linux

package engine

import "fmt"

func startProtocolQueue(p *protocolEngine) (protocolQueueIO, error) {
	return nil, fmt.Errorf("protocol filtering requires Linux NFQUEUE")
}
