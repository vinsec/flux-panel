//go:build !linux

package engine

import (
	"fmt"
	"syscall"
)

func socketInterface(name string) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return fmt.Errorf("interface-bound probes require Linux") }
}

func socketPolicy(name string, mark uint32) func(string, string, syscall.RawConn) error {
	return socketInterface(name)
}
