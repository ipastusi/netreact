package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

func Test_macToVendor(t *testing.T) {
	xerox, _ := hex.DecodeString("000000000000")
	hp, _ := hex.DecodeString("fc15b4000000")
	nokia, _ := hex.DecodeString("fc1ca1000000")
	ieee, _ := hex.DecodeString("fcffaa000000")
	unknownBeforeHp, _ := hex.DecodeString("fc15b3000000")
	unknownAfterHp, _ := hex.DecodeString("fc15b5000000")

	events := []struct {
		name           string
		mac            net.HardwareAddr
		expectedVendor string
	}{
		{"First entry", net.HardwareAddr(xerox), "XEROX CORPORATION"},
		{"Hewlett Packard", net.HardwareAddr(hp), "Hewlett Packard"},
		{"Nokia", net.HardwareAddr(nokia), "Nokia"},
		{"Last entry", net.HardwareAddr(ieee), "IEEE Registration Authority"},
		{"Nonexistent before HP", net.HardwareAddr(unknownBeforeHp), "Unknown"},
		{"Nonexistent after HP", net.HardwareAddr(unknownAfterHp), "Unknown"},
	}

	for _, e := range events {
		t.Run(e.name, func(t *testing.T) {
			vendor := macToVendor(e.mac)
			if vendor != e.expectedVendor {
				t.Fatal(fmt.Sprintf("Incorrect vendor %v for MAC %v, expected %v", vendor, e.mac, e.expectedVendor))
			}
		})
	}
}
