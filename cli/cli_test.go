package cli

import (
	"net"
	"testing"
)

func Test_processFlags(t *testing.T) {
	t.Parallel()

	validIface, _ := net.InterfaceByIndex(1)

	customFlags := Flags{
		IfaceName:         validIface.Name,
		LogFileName:       "arp.log",
		StateFileName:     "nrstate.json",
		PromiscMode:       true,
		EventDir:          "../out",
		UiEnabled:         false,
		Filter:            "arp and src host not 0.0.0.0",
		PacketEventFilter: "1000000",
		HostEventFilter:   "1000000",
		ExpectedCidrRange: "192.168.1.0/24",
		AutoCleanupDelay:  5,
	}

	data := map[string]struct {
		flags Flags
		ok    bool
	}{
		"default values":                    {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "0.0.0.0/0", AutoCleanupDelay: 0}, true},
		"custom values":                     {customFlags, true},
		"invalid package event filter len":  {Flags{PacketEventFilter: "1111111", HostEventFilter: "111111"}, false},
		"invalid package event filter flag": {Flags{PacketEventFilter: "0000002", HostEventFilter: "1111111"}, false},
		"invalid host event filter len":     {Flags{PacketEventFilter: "1111111", HostEventFilter: "111111"}, false},
		"invalid host event filter flag":    {Flags{PacketEventFilter: "1111111", HostEventFilter: "1111112"}, false},
		"nonexistent event dir":             {Flags{IfaceName: validIface.Name, EventDir: "nonexistent", PacketEventFilter: "1111111", HostEventFilter: "1111111"}, false},
		"missing iface":                     {Flags{IfaceName: "", PromiscMode: false, PacketEventFilter: "1111111", HostEventFilter: "1111111"}, false},
		"invalid iface":                     {Flags{IfaceName: "eth99", PromiscMode: false, PacketEventFilter: "1111111", HostEventFilter: "1111111"}, false},
		"expected cidr range rfc 1918":      {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "10.0.0.0/16"}, true},
		"expected cidr range ipv6":          {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "2001:db8::/32"}, false},
		"invalid cidr range 1":              {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "0.0.0.0/33"}, false},
		"invalid cidr range 2":              {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "invalid"}, false},
		"nonexistent ip exclude file":       {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "0.0.0.0/0", ExcludeIPs: "nonexistent"}, false},
		"nonexistent mac exclude file":      {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "0.0.0.0/0", ExcludeMACs: "nonexistent"}, false},
		"nonexistent ip-mac exclude file":   {Flags{IfaceName: validIface.Name, PacketEventFilter: "1111111", HostEventFilter: "1111111", ExpectedCidrRange: "0.0.0.0/0", ExcludePairs: "nonexistent"}, false},
	}

	for name, d := range data {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := processFlags(d.flags)
			if (err == nil) != d.ok {
				t.Fatalf("unexpected result, expected ok: %v, got error: %v", d.ok, err)
			}
		})
	}
}
