package engine

import (
	"fmt"
	"strings"
)

// Older nft parsers reject one numeric time component above uint32, even
// though the kernel timeout is uint64. Compound units retain millisecond
// precision for multi-month user authorizations without shortening expiry.
func nftTimeoutMilliseconds(ms int64) string {
	if ms <= int64(^uint32(0)) {
		return fmt.Sprintf("%dms", ms)
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
