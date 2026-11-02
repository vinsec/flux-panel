package engine

func (k *NativeKernel) Quiesce() error { return k.QuiesceTokens(nil) }
func (k *NativeKernel) QuiesceTokens(tokens []uint32) error {
	return k.Native.gate(tokens, false, false)
}
func (k *NativeKernel) QuiesceNewTokens(tokens []uint32) error {
	return k.Native.gate(tokens, true, false)
}
func (k *NativeKernel) Activate() error { return k.Native.gate(nil, false, true) }
func (k *NativeKernel) SyncCredits(s State) error {
	if e := k.P1.quota.sync(s); e != nil {
		return e
	}
	return k.Native.updateControl(s)
}
func (k *NativeKernel) UpdateControl(s State) error { return k.Native.updateControl(s) }
func (k *NativeKernel) CanRenewCredits(before, after State) (bool, error) {
	return k.P1.quota.canRenew(before, after)
}
func (k *NativeKernel) RenewCredits(before, after State) error { return k.P1.quota.renew(after) }
