//go:build !linux

package engine

import "context"

func (k *NativeKernel) StartAddressWatcher(context.Context) error { return nil }
