package main

import (
	"fmt"
	"github.com/ipastusi/netreact/cache"
	"github.com/ipastusi/netreact/event"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testLogFileName = "test.log"
)

func Test_processArpEvents(t *testing.T) {
	// cleanup generated files
	defer func() {
		if _, err := os.Stat(testLogFileName); err == nil {
			err = os.Remove(testLogFileName)
			if err != nil {
				t.Fatal("error removing test log file:", err)
			}
		}
	}()

	eventDir := "out"
	logHandler := getLogHandler(t)
	janitor, err := event.NewEventJanitor(logHandler, eventDir, 1)
	if err != nil {
		t.Fatal("unexpected error creating event janitor")
	}
	janitor.Start()

	rpiMac, _ := net.ParseMAC("2c:cf:67:0c:6c:a4")
	unknownMac, _ := net.ParseMAC("31:0c:8a:cb:8f:ab")
	excludedMac, _ := net.ParseMAC("31:0c:8a:00:00:02")
	hpMac, _ := net.ParseMAC("b4:b6:86:01:02:03")
	hpMac2, _ := net.ParseMAC("b4:b6:86:01:02:04")
	dellMac, _ := net.ParseMAC("f8:bc:12:01:02:03")

	excludedIPs := map[string]struct{}{"192.168.1.111": {}}
	excludedMACs := map[string]struct{}{"31:0c:8a:00:00:01": {}}
	excludedPairs := map[string]struct{}{"192.168.1.112,31:0c:8a:00:00:02": {}}
	filter := event.NewArpEventFilter(excludedIPs, excludedMACs, excludedPairs)

	hostCache := cache.NewHostCache()
	ipToMac, macToIp := hostCache.IpAndMacMaps()
	packetEventFilter := "1111111"
	hostEventFilter := "1111111"
	handler := event.NewArpEventHandler(logHandler, eventDir, packetEventFilter, hostEventFilter, "192.168.1.0/24", ipToMac, macToIp)

	events := []struct {
		arpEvent           event.ArpEvent
		expectedCacheSize  int
		expectedCount      int
		expectedMacVendor  string
		expectedEventCodes []event.Type
		excluded           bool
	}{
		{event.ArpEvent{net.ParseIP("192.168.1.100"), rpiMac, time.Now().UnixMilli() + 0}, 1, 1, "Raspberry Pi (Trading) Ltd", []event.Type{event.NewPacket, event.NewHost}, false},
		{event.ArpEvent{net.ParseIP("192.168.1.200"), unknownMac, time.Now().UnixMilli() + 1}, 2, 1, "Unknown", []event.Type{event.NewPacket, event.NewHost}, false},
		{event.ArpEvent{net.ParseIP("192.168.1.100"), rpiMac, time.Now().UnixMilli() + 2}, 2, 2, "Raspberry Pi (Trading) Ltd", []event.Type{event.NewPacket}, false},
		{event.ArpEvent{net.ParseIP("192.168.1.200"), unknownMac, time.Now().UnixMilli() + 3}, 2, 2, "Unknown", []event.Type{event.NewPacket}, false},
		{event.ArpEvent{net.ParseIP("0.0.0.0"), hpMac, time.Now().UnixMilli() + 4}, 3, 1, "Hewlett Packard", []event.Type{event.NewPacket, event.NewHost, event.NewUnspecifiedPacket, event.NewUnspecifiedHost}, false},
		{event.ArpEvent{net.ParseIP("169.254.10.20"), dellMac, time.Now().UnixMilli() + 5}, 4, 1, "Dell Inc.", []event.Type{event.NewPacket, event.NewHost, event.NewLinkLocalUnicastPacket, event.NewLinkLocalUnicastHost}, false},
		{event.ArpEvent{net.ParseIP("255.255.255.255"), unknownMac, time.Now().UnixMilli() + 6}, 5, 1, "Unknown", []event.Type{event.NewPacket, event.NewHost, event.NewBroadcastPacket, event.NewBroadcastHost, event.NewIpForMacPacket, event.NewIpForMacHost}, false},
		{event.ArpEvent{net.ParseIP("192.168.2.1"), unknownMac, time.Now().UnixMilli() + 7}, 6, 1, "Unknown", []event.Type{event.NewPacket, event.NewHost, event.NewUnexpectedIpPacket, event.NewUnexpectedIpHost, event.NewIpForMacPacket, event.NewIpForMacHost}, false},
		{event.ArpEvent{net.ParseIP("0.0.0.0"), hpMac2, time.Now().UnixMilli() + 8}, 7, 1, "Hewlett Packard", []event.Type{event.NewPacket, event.NewHost, event.NewUnspecifiedPacket, event.NewUnspecifiedHost, event.NewMacForIpPacket, event.NewMacForIpHost}, false},
		{event.ArpEvent{net.ParseIP("192.168.1.111"), unknownMac, time.Now().UnixMilli() + 9}, 7, 0, "Unknown", []event.Type{}, true},
		{event.ArpEvent{net.ParseIP("192.168.1.111"), excludedMac, time.Now().UnixMilli() + 10}, 7, 0, "Unknown", []event.Type{}, true},
		{event.ArpEvent{net.ParseIP("192.168.1.112"), excludedMac, time.Now().UnixMilli() + 11}, 7, 0, "Unknown", []event.Type{}, true},
	}

	for i, e := range events {
		// process test event
		processArpEvent(e.arpEvent, hostCache, filter, handler, nil)

		// cache checks
		hostCacheSize := len(hostCache.Items)
		if hostCacheSize != e.expectedCacheSize {
			t.Fatalf("unexpected cache size, expected: %v, got: %v", hostCacheSize, e.expectedCacheSize)
		}

		// excluded entries
		hostKey := cache.KeyFromArpEvent(e.arpEvent)
		hostDetails := hostCache.Host(hostKey)
		if e.excluded {
			if hostDetails.Count != 0 || hostDetails.FirstTs != 0 || hostDetails.LastTs != 0 {
				t.Fatalf("unexpected values for excluded entry, count: %v, first: %v, last: %v", hostDetails.Count, hostDetails.FirstTs, hostDetails.LastTs)
			}
			continue
		}

		// count checks
		if hostDetails.Count != e.expectedCount {
			t.Fatalf("unexpected event count, expected: %v, got: %v", hostDetails.Count, e.expectedCount)
		}

		// check timestamps
		if e.expectedCount == 1 {
			if hostDetails.FirstTs != hostDetails.LastTs {
				t.Fatalf("unexpected timestamp difference, first: %v, last: %v", hostDetails.FirstTs, hostDetails.LastTs)
			}
		} else if hostDetails.FirstTs >= hostDetails.LastTs {
			t.Fatalf("unexpected timestamp difference, first: %v, last: %v", hostDetails.FirstTs, hostDetails.LastTs)
		}

		// check execution log
		testLogBytes, err := os.ReadFile(testLogFileName)
		if err != nil {
			t.Fatal("error reading execution log:", err)
		}

		testLog := string(testLogBytes)
		testLogLines := strings.Split(testLog, "\n")
		testlogLineCount := len(testLogLines)
		expectedLineCount := i + 2
		if testlogLineCount != expectedLineCount {
			t.Fatalf("unexpected number entries in test log file, expected: %v, got: %v", expectedLineCount, testlogLineCount)
		}

		lastLogRecord := testLogLines[len(testLogLines)-2]
		if !strings.Contains(lastLogRecord, e.arpEvent.Ip.String()) {
			t.Fatal("IP address not found in test log for iteration:", i)
		}
		if !strings.Contains(lastLogRecord, e.arpEvent.Mac.String()) {
			t.Fatal("MAC address not found in test log for iteration:", i)
		}

		// check event files
		var allEventCodes []event.Type
		for i := 0; i < len(packetEventFilter); i++ {
			allEventCodes = append(allEventCodes, event.Type(100+i), event.Type(200+i))
		}

		for _, eventCode := range allEventCodes {
			eventFileName := fmt.Sprintf("out/netreact-%v-%v.json", e.arpEvent.Ts, eventCode)
			if !slices.Contains(e.expectedEventCodes, eventCode) {
				// we don't expect to find a file from outside of the pre-determined list of event types
				if _, err = os.Stat(eventFileName); err == nil {
					t.Fatal("unexpected event file exists:", eventFileName)
				}
				continue
			}

			eventFileBytes, err := os.ReadFile(eventFileName)
			if err != nil {
				t.Fatal("error reading event file:", err)
			}

			eventFile := string(eventFileBytes)
			if !strings.Contains(eventFile, e.arpEvent.Ip.String()) {
				t.Fatal("IP address not found in responder log for iteration:", i)
			}
			if !strings.Contains(eventFile, e.arpEvent.Mac.String()) {
				t.Fatal("MAC address not found in responder log for iteration:", i)
			}
			if !strings.Contains(eventFile, e.expectedMacVendor) {
				t.Fatal("MAC vendor not found in responder log for iteration:", i)
			}
		}
	}

	// let the janitor do its job
	time.Sleep(time.Duration(2500) * time.Millisecond)
}

func getLogHandler(t *testing.T) slog.Handler {
	logFile, err := os.OpenFile(testLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal("error opening log file:", err)
	}
	return slog.NewJSONHandler(logFile, nil)
}
