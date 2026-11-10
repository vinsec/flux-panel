package engine

import (
	"fmt"
	"strings"
)

// nft 1.0.6 rejects numeric time components longer than eight digits,
// including leading zeroes. Always normalize units instead of guessing an
// integer-width limit. This preserves the exact deadline at every duration.
func nftTimeoutMilliseconds(ms int64) string {
	if ms <= 0 {
		return "0ms"
	}
	var out strings.Builder
	for _, u := range []struct {
		size   int64
		suffix string
	}{{86400000, "d"}, {3600000, "h"}, {60000, "m"}, {1000, "s"}, {1, "ms"}} {
		if n := ms / u.size; n > 0 {
			fmt.Fprintf(&out, "%d%s", n, u.suffix)
			ms %= u.size
		}
	}
	return out.String()
}
