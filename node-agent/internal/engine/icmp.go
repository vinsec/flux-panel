package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func controlIdentity(rules map[string]Spec, allowed map[uint32]bool) (string, error) {
	var bitmap [2 * 8192]byte
	for _, rule := range rules {
		if rule.Deleted {
			continue
		}
		if rule.Token > 65535 {
			return "", fmt.Errorf("invalid control token")
		}
		bitmap[rule.Token>>3] |= byte(1 << (rule.Token & 7))
		if allowed[rule.Token] {
			bitmap[8192+(rule.Token>>3)] |= byte(1 << (rule.Token & 7))
		}
	}
	hash := sha256.Sum256(bitmap[:])
	return hex.EncodeToString(hash[:]), nil
}
