package engine

import (
	"fmt"
	"strings"
)

const metaSet = "FPV3_META"

func (k *IPTables) ClaimLedger(epoch string) (string, error) {
	if k.Native != nil {
		k.P1.epoch = epoch
		return k.Native.claim(epoch, false)
	}
	if k.P1 != nil {
		k.P1.epoch = epoch
	}
	saved, e := k.readSet(metaSet)
	if e != nil {
		return "", e
	}
	v, ok := parseSet(saved)["192.0.2.255"]
	if !ok {
		return "", fmt.Errorf("kernel ownership marker is missing")
	}
	prefix := owner + "|epoch="
	if strings.HasPrefix(v.Comment, prefix) {
		parts := strings.Split(strings.TrimPrefix(v.Comment, prefix), "|instance=")
		if parts[0] != epoch {
			return "", fmt.Errorf("persistent state does not match the kernel accounting epoch")
		}
		if len(parts) == 2 && len(parts[1]) == 32 {
			return parts[1], nil
		}
	} else if v.Comment != owner {
		return "", fmt.Errorf("kernel ownership marker has unknown identity")
	}
	return k.RotateLedger(epoch)
}
func (k *IPTables) ClaimEpoch(epoch string) error { _, e := k.ClaimLedger(epoch); return e }
func (k *IPTables) RotateLedger(epoch string) (string, error) {
	if k.Native != nil {
		return k.Native.claim(epoch, true)
	}
	id := identity()
	_, e := k.run("ipset", "", "-exist", "add", metaSet, "192.0.2.255", "comment", owner+"|epoch="+epoch+"|instance="+id)
	return id, e
}
