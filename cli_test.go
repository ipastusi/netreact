package main

import (
	"net"
	"testing"
)

func Test_processCliFlags(t *testing.T) {
	validIface, _ := net.InterfaceByIndex(1)

	customFlags := CliFlags{
		ifaceName:         validIface.Name,
		logFileName:       "arp.log",
		stateFileName:     "nrstate.json",
		promiscMode:       true,
		eventDir:          "events",
		uiEnabled:         false,
		filter:            "arp and src host not 0.0.0.0",
		packetEventFilter: "1000000",
		hostEventFilter:   "1000000",
		expectedCidrRange: "192.168.1.0/24",
		autoCleanupDelay:  5,
	}

	data := []struct {
		name  string
		flags CliFlags
		ok    bool
	}{
		{"default values", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "0.0.0.0/0", autoCleanupDelay: 0}, true},
		{"custom values", customFlags, true},
		{"invalid package event filter len", CliFlags{packetEventFilter: "1111111", hostEventFilter: "111111"}, false},
		{"invalid package event filter flag", CliFlags{packetEventFilter: "0000002", hostEventFilter: "1111111"}, false},
		{"invalid host event filter len", CliFlags{packetEventFilter: "1111111", hostEventFilter: "111111"}, false},
		{"invalid host event filter flag", CliFlags{packetEventFilter: "1111111", hostEventFilter: "1111112"}, false},
		{"nonexistent event dir", CliFlags{ifaceName: validIface.Name, eventDir: "nonexistent", packetEventFilter: "1111111", hostEventFilter: "1111111"}, false},
		{"missing iface", CliFlags{ifaceName: "", promiscMode: false, packetEventFilter: "1111111", hostEventFilter: "1111111"}, false},
		{"invalid iface", CliFlags{ifaceName: "eth99", promiscMode: false, packetEventFilter: "1111111", hostEventFilter: "1111111"}, false},
		{"expected cidr range rfc 1918", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "10.0.0.0/16"}, true},
		{"expected cidr range ipv6", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "2001:db8::/32"}, false},
		{"invalid cidr range 1", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "0.0.0.0/33"}, false},
		{"invalid cidr range 2", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "invalid"}, false},
		{"nonexistent ip exclude file", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "0.0.0.0/0", excludeIPs: "nonexistent"}, false},
		{"nonexistent mac exclude file", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "0.0.0.0/0", excludeMACs: "nonexistent"}, false},
		{"nonexistent ip-mac exclude file", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111111", hostEventFilter: "1111111", expectedCidrRange: "0.0.0.0/0", excludePairs: "nonexistent"}, false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			err := processCliFlags(d.flags)
			if (err == nil) != d.ok {
				t.Fatalf("unexpected result, expected ok: %v, got error: %v", d.ok, err)
			}
		})
	}
}
