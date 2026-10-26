//go:build !linux

package control

import "net"

func helperPeerAllowed(*net.UnixConn, uint32) bool { return false }
