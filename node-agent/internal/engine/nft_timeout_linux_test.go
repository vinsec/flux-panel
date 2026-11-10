package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Real parser checks run in a fresh network namespace and use check-only mode.
// They cannot read or modify the host forwarding rules.
func TestNFTTimeoutParserCompatibility(t *testing.T) {
	if os.Getenv("FLUX_NFT_PARSER_TEST") != "1" {
		t.Skip("FLUX_NFT_PARSER_TEST=1 requires disposable Linux root")
	}
	for _, ms := range []int64{1, 99999999, 100000000, 2147483647, 2147483648, 4294967295, 4294967296, 49 * 86400000, 52 * 86400000, 138 * 86400000} {
		t.Run(fmt.Sprint(ms), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "unshare", "--net", "nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader("add table inet flux_parser_test\nadd set inet flux_parser_test s { type mark; flags timeout; }\nadd element inet flux_parser_test s { 1 timeout " + nftTimeoutMilliseconds(ms) + " }\n")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft rejected %dms encoded as %q: %v: %s", ms, nftTimeoutMilliseconds(ms), err, output)
			}
		})
	}
}
