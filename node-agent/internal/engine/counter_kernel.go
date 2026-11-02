package engine

func (k *NativeKernel) SnapshotDetailed() (map[string]uint64, []counterRecord, error) {
	return k.Native.snapshot()
}
func (k *NativeKernel) References() (map[string]bool, error)    { return k.Native.references() }
func (k *NativeKernel) RemoveCounters(r []counterRecord) error  { return k.Native.restore(r, true) }
func (k *NativeKernel) RestoreCounters(r []counterRecord) error { return k.Native.restore(r, false) }
