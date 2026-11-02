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
	var err error
	s, err = k.executionState(s)
	if err != nil {
		return err
	}
	if e := k.P1.quota.sync(s); e != nil {
		return e
	}
	return k.Native.updateControl(s)
}
func (k *NativeKernel) UpdateControl(s State) error {
	s, e := k.executionState(s)
	if e != nil {
		return e
	}
	return k.Native.updateControl(s)
}
func (k *NativeKernel) CanRenewCredits(before, after State) (bool, error) {
	return k.P1.quota.canRenew(before, after)
}
func (k *NativeKernel) RenewCredits(before, after State) error { return k.P1.quota.renew(after) }

func (k *NativeKernel) executionState(s State) (State, error) {
	if k.Gost == nil || k.Mode != "gost" {
		return s, nil
	}
	plan, _, e := k.Gost.project(mapSpecs(s.Rules))
	if e != nil {
		return s, e
	}
	s.Rules = map[string]Spec{}
	for _, r := range plan {
		s.Rules[r.ID] = r
	}
	return s, nil
}
