package engine

func (k *NativeKernel) ClaimLedger(epoch string) (string, error) {
	k.P1.epoch = epoch
	return k.Native.claim(epoch, false)
}
func (k *NativeKernel) ClaimEpoch(epoch string) error             { _, e := k.ClaimLedger(epoch); return e }
func (k *NativeKernel) RotateLedger(epoch string) (string, error) { return k.Native.claim(epoch, true) }
