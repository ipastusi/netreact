package main

import (
	"fmt"
	"net"
	"testing"
)

func Test_macToVendor(t *testing.T) {
	xerox, _ := net.ParseMAC("00:00:00:00:00:00")
	hp, _ := net.ParseMAC("fc:15:b4:00:00:00")
	nokia, _ := net.ParseMAC("fc:1c:a1:00:00:00")
	ieee, _ := net.ParseMAC("fc:ff:aa:00:00:00")
	unknownBeforeHp, _ := net.ParseMAC("fc:15:b3:00:00:00")
	unknownAfterHp, _ := net.ParseMAC("fc:15:b5:00:00:00")

	events := []struct {
		name           string
		mac            net.HardwareAddr
		expectedVendor string
	}{
		{"First entry", xerox, "XEROX CORPORATION"},
		{"Hewlett Packard", hp, "Hewlett Packard"},
		{"Nokia", nokia, "Nokia"},
		{"Last entry", ieee, "IEEE Registration Authority"},
		{"Nonexistent before HP", unknownBeforeHp, "Unknown"},
		{"Nonexistent after HP", unknownAfterHp, "Unknown"},
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
