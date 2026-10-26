//go:build !linux

package engine

import "context"

func (k *IPTables) StartAddressWatcher(context.Context) error { return nil }
