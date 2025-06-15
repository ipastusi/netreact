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
		packetEventFilter: "1000",
		hostEventFilter:   "1000",
	}

	data := []struct {
		name  string
		flags CliFlags
		ok    bool
	}{
		{"default values", CliFlags{ifaceName: validIface.Name, packetEventFilter: "1111", hostEventFilter: "1111"}, true},
		{"custom values", customFlags, true},
		{"invalid package event filter len", CliFlags{packetEventFilter: "11111", hostEventFilter: "1111"}, false},
		{"invalid package event filter flag", CliFlags{packetEventFilter: "0002", hostEventFilter: "1111"}, false},
		{"invalid host event filter len", CliFlags{packetEventFilter: "1111", hostEventFilter: "111"}, false},
		{"invalid host event filter flag", CliFlags{packetEventFilter: "1111", hostEventFilter: "1112"}, false},
		{"nonexistent event dir", CliFlags{ifaceName: validIface.Name, eventDir: "nonexistent", packetEventFilter: "1111", hostEventFilter: "1111"}, false},
		{"missing iface", CliFlags{ifaceName: "", promiscMode: false, packetEventFilter: "1111", hostEventFilter: "1111"}, false},
		{"invalid iface", CliFlags{ifaceName: "eth99", promiscMode: false, packetEventFilter: "1111", hostEventFilter: "1111"}, false},
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
