package engine

import "testing"

func TestNFTTimeoutLongAuthorizationUsesBoundedComponents(t *testing.T) {
	for _, tc := range []struct {
		ms   int64
		want string
	}{{0, "0ms"}, {1, "1ms"}, {30000, "30s"}, {99999999, "1d3h46m39s999ms"}, {100000000, "1d3h46m40s"}, {2147483647, "24d20h31m23s647ms"}, {4294967295, "49d17h2m47s295ms"}, {4294967296, "49d17h2m47s296ms"}, {4868730272, "56d8h25m30s272ms"}, {12558330272, "145d8h25m30s272ms"}} {
		if got := nftTimeoutMilliseconds(tc.ms); got != tc.want {
			t.Fatalf("%d: got %q, want %q", tc.ms, got, tc.want)
		}
	}
}
