package main

import (
	"fmt"
	"log/slog"
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
	defer func() {
		if _, err := os.Stat(testLogFileName); err == nil {
			err = os.Remove(testLogFileName)
			if err != nil {
				t.Fatal("error removing test log file:", err)
			}
		}

		files, err := filepath.Glob("testdir/netreact*.json")
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

	eventDir := filepath.Join(pwd, "testdir")
	h := newArpEventHandler(nil, getLogHandler(t), eventDir)
	cache := newCache()

	events := []struct {
		arpEvent          ArpEvent
		expectedCacheSize int
		expectedCount     int
	}{
		{ArpEvent{[]byte{192, 168, 1, 100}, []byte{0x41, 0xC0, 0x5B, 0x0C, 0x6C, 0xA4}, time.Now().UnixMilli() + 0}, 1, 1},
		{ArpEvent{[]byte{192, 168, 1, 200}, []byte{0x31, 0x0C, 0x8A, 0xCB, 0x8F, 0xAB}, time.Now().UnixMilli() + 1}, 2, 1},
		{ArpEvent{[]byte{192, 168, 1, 100}, []byte{0x41, 0xC0, 0x5B, 0x0C, 0x6C, 0xA4}, time.Now().UnixMilli() + 2}, 2, 2},
		{ArpEvent{[]byte{192, 168, 1, 100}, []byte{0x31, 0x0C, 0x8A, 0xCB, 0x8F, 0xAB}, time.Now().UnixMilli() + 3}, 3, 1},
	}

	for i, e := range events {
		processArpEvent(e.arpEvent, cache, h)

		// cache checks
		cacheSize := len(cache.items)
		if cacheSize != e.expectedCacheSize {
			t.Fatalf("unexpected cache size, expected: %v, got: %v", cacheSize, e.expectedCacheSize)
		}

		value := cache.get(e.arpEvent)
		if e.expectedCount == 1 {
			if value.firstTs != value.lastTs {
				t.Fatalf("unexpected timestamp difference, first: %v, last: %v", value.firstTs, value.lastTs)
			}
		} else if value.firstTs >= value.lastTs {
			t.Fatalf("unexpected timestamp difference, first: %v, last: %v", value.firstTs, value.lastTs)
		}

		// log checks
		testLogBytes, err := os.ReadFile(testLogFileName)
		if err != nil {
			t.Fatal("error reading test log file:", err)
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

		// event file checks
		eventFileName := fmt.Sprintf("testdir/netreact-%v.json", e.arpEvent.ts)
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
	}
}

func getLogHandler(t *testing.T) slog.Handler {
	logFile, err := os.OpenFile(testLogFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal("error opening log file:", err)
	}
	return slog.NewJSONHandler(logFile, nil)
}
