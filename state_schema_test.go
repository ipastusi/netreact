package main

import (
	"errors"
	"testing"
)

func Test_validateState(t *testing.T) {
	state := []byte(`{
		"items": [
    		{
				"ip": "192.168.0.1",
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1751972610000,
        		"lastTs": 1751972610000,
        		"count": 10
			}
    ]}`)

	errs := validateState(state)
	if len(errs) > 0 {
		t.Fatal("unexpected validation error:", errs)
	}
}

func Test_validateStateEmpty(t *testing.T) {
	state := []byte(`{
        "items": []
    }`)

	errs := validateState(state)
	if len(errs) > 0 {
		t.Fatal("unexpected validation error:", errs)
	}
}

func Test_validateStateInvalid(t *testing.T) {
	state := []byte(`{
		"items": [
    		{
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1751972610000,
        		"lastTs": 1751972610000,
        		"count": 10
			}
    ]}`)

	errs := validateState(state)
	if len(errs) != 1 && !errors.Is(errs[0], errors.New("Item at index 0 does not match the schema")) {
		t.Fatal("unexpected validation error:", errs)
	}
}
