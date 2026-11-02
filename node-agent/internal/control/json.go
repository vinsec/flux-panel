package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func strictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(value); e != nil {
		return e
	}
	var trailing any
	if e := decoder.Decode(&trailing); e != io.EOF {
		return fmt.Errorf("unexpected trailing command data")
	}
	return nil
}
