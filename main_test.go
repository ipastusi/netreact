package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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

		files, err := filepath.Glob("events/netreact*.json")
		if err != nil {
			t.Fatal("error getting matching files:", err)
		}
		for _, file := range files {
			err = os.Remove(file)
			if err != nil {
				t.Fatal("error removing event files:", err)
			}
		}
	}()

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal("error getting pwd:", err)
	}

	eventDir := filepath.Join(pwd, "events")
	h := newArpEventHandler(nil, getLogHandler(t), eventDir)
	cache := newCache()

	rpiMac, _ := net.ParseMAC("2c:cf:67:0c:6c:a4")
	unknownMac, _ := net.ParseMAC("31:0c:8a:cb:8f:ab")
	hpMac, _ := net.ParseMAC("b4:b6:86:01:02:03")
	dellMac, _ := net.ParseMAC("f8:bc:12:01:02:03")

	events := []struct {
		arpEvent           ArpEvent
		expectedCacheSize  int
		expectedCount      int
		expectedMacVendor  string
		expectedEventCodes []EventType
	}{
		{ArpEvent{net.ParseIP("192.168.1.100"), rpiMac, time.Now().UnixMilli() + 0}, 1, 1, "Raspberry Pi (Trading) Ltd", []EventType{NewPacket, NewHost}},
		{ArpEvent{net.ParseIP("192.168.1.200"), unknownMac, time.Now().UnixMilli() + 1}, 2, 1, "Unknown", []EventType{NewPacket, NewHost}},
		{ArpEvent{net.ParseIP("192.168.1.100"), rpiMac, time.Now().UnixMilli() + 2}, 2, 2, "Raspberry Pi (Trading) Ltd", []EventType{NewPacket}},
		{ArpEvent{net.ParseIP("192.168.1.200"), unknownMac, time.Now().UnixMilli() + 3}, 2, 2, "Unknown", []EventType{NewPacket}},
		{ArpEvent{net.ParseIP("0.0.0.0"), hpMac, time.Now().UnixMilli() + 4}, 3, 1, "Hewlett Packard", []EventType{NewPacket, NewHost, NewUnspecifiedPacket, NewUnspecifiedHost}},
		{ArpEvent{net.ParseIP("169.254.10.20"), dellMac, time.Now().UnixMilli() + 5}, 4, 1, "Dell Inc.", []EventType{NewPacket, NewHost, NewLinkLocalUnicastPacket, NewLinkLocalUnicastPacket}},
		{ArpEvent{net.ParseIP("255.255.255.255"), unknownMac, time.Now().UnixMilli() + 6}, 5, 1, "Unknown", []EventType{NewPacket, NewHost, NewBroadcastPacket, NewBroadcastHost}},
	}

	for i, e := range events {
		// process test event
		processArpEvent(e.arpEvent, cache, h)

		// cache checks
		cacheSize := len(cache.Items)
		if cacheSize != e.expectedCacheSize {
			t.Fatalf("unexpected cache size, expected: %v, got: %v", cacheSize, e.expectedCacheSize)
		}

		// check timestamps
		value := cache.get(e.arpEvent)
		if e.expectedCount == 1 {
			if value.FirstTs != value.LastTs {
				t.Fatalf("unexpected timestamp difference, first: %v, last: %v", value.FirstTs, value.LastTs)
			}
		} else if value.FirstTs >= value.LastTs {
			t.Fatalf("unexpected timestamp difference, first: %v, last: %v", value.FirstTs, value.LastTs)
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
		if !strings.Contains(lastLogRecord, e.arpEvent.ip.String()) {
			t.Fatal("IP address not found in test log for iteration:", i)
		}
		if !strings.Contains(lastLogRecord, e.arpEvent.mac.String()) {
			t.Fatal("MAC address not found in test log for iteration:", i)
		}

		// check event files
		for _, eventCode := range e.expectedEventCodes {
			eventFileName := fmt.Sprintf("events/netreact-%v-%v.json", e.arpEvent.ts, eventCode)
			eventFileBytes, err := os.ReadFile(eventFileName)
			if err != nil {
				t.Fatal("error reading event file:", err)
			}

			eventFile := string(eventFileBytes)
			if !strings.Contains(eventFile, e.arpEvent.ip.String()) {
				t.Fatal("IP address not found in responder log for iteration:", i)
			}
			if !strings.Contains(eventFile, e.arpEvent.mac.String()) {
				t.Fatal("MAC address not found in responder log for iteration:", i)
			}
			if !strings.Contains(eventFile, e.expectedMacVendor) {
				t.Fatal("MAC vendor not found in responder log for iteration:", i)
			}
		}
	}
}

func getLogHandler(t *testing.T) slog.Handler {
	logFile, err := os.OpenFile(testLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal("error opening log file:", err)
	}
	return slog.NewJSONHandler(logFile, nil)
}
