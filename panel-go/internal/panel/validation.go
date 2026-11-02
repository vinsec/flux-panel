package panel

import (
	"math/big"
	"strings"
)

func validateDTO(dto string, m M) {
	for _, r := range dtoRules[dto] {
		v := m[r.Field]
		bad := false
		switch r.Kind {
		case "NotNull":
			bad = v == nil
		case "NotBlank":
			bad = v == nil || strings.TrimSpace(str(v)) == ""
		case "Min", "Max", "DecimalMin":
			if v != nil {
				n, ok := new(big.Rat).SetString(str(v))
				b, _ := new(big.Rat).SetString(r.Value)
				if !ok {
					bad = true
				} else if r.Kind == "Max" {
					bad = n.Cmp(b) > 0
				} else {
					bad = n.Cmp(b) < 0
				}
			}
		}
		if bad {
			panic(apiError{r.Message, 500, 200})
		}
	}
}
