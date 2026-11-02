//go:build !linux

package engine

import "fmt"

type localProgramInfo struct {
	Type, ID uint32
	Tag      [8]byte
}

func inspectLocalProgramPin(string) (localProgramInfo, error) {
	return localProgramInfo{}, fmt.Errorf("local BPF preparation requires Linux")
}
func PrepareLocalShaping() (map[string]any, error) {
	return nil, fmt.Errorf("local BPF preparation requires Linux")
}
