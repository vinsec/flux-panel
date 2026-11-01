//go:build !linux

package engine

import "fmt"

func (n *NativeNFT) readCounterObjects() ([]nativeCounter, error) {
	return nil, fmt.Errorf("native nft counter sampling requires Linux")
}

func readCounterObjectsTable(string) ([]nativeCounter, error) {
	return nil, fmt.Errorf("nft counter sampling requires Linux")
}
