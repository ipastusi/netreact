package main

import (
	"net"
	"testing"
)

func Test_processCliFlags(t *testing.T) {
	validIface, _ := net.InterfaceByIndex(1)

	customFlags := CliFlags{
		ifaceName:     validIface.Name,
		logFileName:   "arp.log",
		stateFileName: "nrstate.json",
		promiscMode:   true,
		eventDir:      "events",
		uiEnabled:     false,
		filter:        "arp and src host not 0.0.0.0",
	}

	data := []struct {
		name  string
		flags CliFlags
		ok    bool
	}{
		{"default values", CliFlags{ifaceName: validIface.Name}, true},
		{"custom values", customFlags, true},
		{"nonexistent event dir", CliFlags{ifaceName: validIface.Name, eventDir: "nonexistent"}, false},
		{"missing iface", CliFlags{ifaceName: "", promiscMode: false}, false},
		{"invalid iface", CliFlags{ifaceName: "eth99", promiscMode: false}, false},
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
