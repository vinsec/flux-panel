package engine

func (k *NativeKernel) BootID() string {
	b, e := k.run("cat", "", "/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "unknown"
	}
	return b
}

func secondsUntil(deadline, now int64) int64 {
	if deadline <= now {
		return 0
	}
	return (deadline - now) / 1000
}
