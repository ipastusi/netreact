package state_test

import (
	"errors"
	"github.com/ipastusi/netreact/state"
	"testing"
)

func Test_ValidateState(t *testing.T) {
	t.Parallel()

	stateBytes := []byte(`{
		"items": [
    		{
				"ip": "192.168.0.1",
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1751972610000,
        		"lastTs": 1751972610000,
        		"count": 10
			}
    ]}`)

	errs := state.ValidateState(stateBytes)
	if len(errs) > 0 {
		t.Fatal("unexpected validation error:", errs)
	}
}

func Test_ValidateStateEmpty(t *testing.T) {
	t.Parallel()

	stateBytes := []byte(`{
        "items": []
    }`)

	errs := state.ValidateState(stateBytes)
	if len(errs) > 0 {
		t.Fatal("unexpected validation error:", errs)
	}
}

func Test_ValidateStateInvalid(t *testing.T) {
	t.Parallel()

	stateBytes := []byte(`{
		"items": [
    		{
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1751972610000,
        		"lastTs": 1751972610000,
        		"count": 10
			}
    ]}`)

	errs := state.ValidateState(stateBytes)
	if len(errs) != 1 && !errors.Is(errs[0], errors.New("Item at index 0 does not match the schema")) {
		t.Fatal("unexpected validation error:", errs)
	}
}
