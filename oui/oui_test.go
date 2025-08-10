package oui_test

import (
	"fmt"
	"github.com/ipastusi/netreact/oui"
	"net"
	"testing"
)

func Test_MacToVendor(t *testing.T) {
	t.Parallel()

	xerox, _ := net.ParseMAC("00:00:00:00:00:00")
	hp, _ := net.ParseMAC("fc:15:b4:00:00:00")
	nokia, _ := net.ParseMAC("fc:1c:a1:00:00:00")
	ieee, _ := net.ParseMAC("fc:ff:aa:00:00:00")
	unknownBeforeHp, _ := net.ParseMAC("fc:15:b3:00:00:00")
	unknownAfterHp, _ := net.ParseMAC("fc:15:b5:00:00:00")
	whitespacePrefixed, _ := net.ParseMAC("54:14:73:00:00:00")

	events := map[string]struct {
		mac            net.HardwareAddr
		expectedVendor string
	}{
		"First entry":           {xerox, "XEROX CORPORATION"},
		"Hewlett Packard":       {hp, "Hewlett Packard"},
		"Nokia":                 {nokia, "Nokia"},
		"Last entry":            {ieee, "IEEE Registration Authority"},
		"Nonexistent before HP": {unknownBeforeHp, "Unknown"},
		"Nonexistent after HP":  {unknownAfterHp, "Unknown"},
		"Whitespace-prefixed":   {whitespacePrefixed, "Wingtech Group (HongKong）Limited"},
	}

	for name, e := range events {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			vendor := oui.MacToVendor(e.mac)
			if vendor != e.expectedVendor {
				t.Fatal(fmt.Sprintf("Incorrect vendor '%v' for MAC %v, expected '%v'", vendor, e.mac, e.expectedVendor))
			}
		})
	}
}
