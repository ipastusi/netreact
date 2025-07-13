package event

import (
	"io"
	"strings"
	"testing"
)

func Test_isExcluded(t *testing.T) {
	excludedIPs := map[string]struct{}{
		"10.0.0.2": {},
		"10.0.0.3": {},
	}

	excludedMACs := map[string]struct{}{
		"31:0c:8a:cb:8f:aa": {},
		"31:0c:8a:cb:8f:ab": {},
		"31:0c:8a:cb:8f:ac": {},
	}

	excludedPairs := map[string]struct{}{
		"10.0.2.1,31:0c:8a:cb:0a:0a": {},
		"10.0.2.2,31:0c:8a:cb:0b:0b": {},
	}

	filter := NewArpEventFilter(excludedIPs, excludedMACs, excludedPairs)

	data := []struct {
		name          string
		mac           string
		ip            string
		shouldExclude bool
	}{
		{"ok", "31:0c:8a:cb:8f:00", "10.0.0.1", false},
		{"excluded ip part only", "31:0c:8a:cb:8f:00", "10.0.2.1", false},
		{"excluded mac part only", "31:0c:8a:cb:0b:0b", "10.0.0.1", false},
		{"excluded ip", "31:0c:8a:cb:8f:00", "10.0.0.2", true},
		{"excluded mac", "31:0c:8a:cb:8f:aa", "10.0.0.1", true},
		{"excluded pair", "31:0c:8a:cb:0a:0a", "10.0.2.1", true},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			isExcluded := filter.IsExcluded(d.ip, d.mac)
			if isExcluded != d.shouldExclude {
				t.Fatalf("unexpected result for IP %v MAC %v, expected ok: %v, got: %v", d.ip, d.mac, d.shouldExclude, isExcluded)
			}
		})
	}
}

func Test_readIPs(t *testing.T) {
	data := []struct {
		name string
		data io.Reader
		size int
		ok   bool
	}{
		{"one", strings.NewReader("10.0.0.1\r"), 1, true},
		{"two", strings.NewReader(" 10.0.0.1\r\n10.0.0.2 "), 2, true},
		{"two with trailing new line", strings.NewReader("10.0.0.1\n10.0.0.2\n"), 2, true},
		{"invalid", strings.NewReader("10.0.0.1\n10.0.0.2\ninvalid"), 0, false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			ips, err := ReadIPs(d.data)
			if (err == nil && !d.ok) || (err != nil && d.ok) {
				t.Fatalf("unexpected result for data %v, expected ok: %v, got error: %v", d.data, d.ok, err)
			}
			if len(ips) != d.size {
				t.Fatalf("unexpected size for data %v, expected ok: %v, got: %v", d.data, d.size, len(ips))
			}
		})
	}
}

func Test_readMACs(t *testing.T) {
	data := []struct {
		name string
		data io.Reader
		size int
		ok   bool
	}{
		{"one", strings.NewReader("00:00:00:00:00:01\r"), 1, true},
		{"two", strings.NewReader(" 00:00:00:00:00:01\r\n00:00:00:00:00:02 "), 2, true},
		{"two with trailing new line", strings.NewReader("00:00:00:00:00:01\n00:00:00:00:00:02\n"), 2, true},
		{"invalid", strings.NewReader("00:00:00:00:00:01\n00:00:00:00:00:02\ninvalid"), 0, false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			ips, err := ReadMACs(d.data)
			if (err == nil && !d.ok) || (err != nil && d.ok) {
				t.Fatalf("unexpected result for data %v, expected ok: %v, got error: %v", d.data, d.ok, err)
			}
			if len(ips) != d.size {
				t.Fatalf("unexpected size for data %v, expected ok: %v, got: %v", d.data, d.size, len(ips))
			}
		})
	}
}

func Test_readPairs(t *testing.T) {
	data := []struct {
		name string
		data io.Reader
		size int
		ok   bool
	}{
		{"one", strings.NewReader("10.0.0.1,00:00:00:00:00:01\r"), 1, true},
		{"two", strings.NewReader(" 10.0.0.1,00:00:00:00:00:01\r\n10.0.0.2,00:00:00:00:00:02 "), 2, true},
		{"two with trailing new line", strings.NewReader("10.0.0.1,00:00:00:00:00:01\n10.0.0.2,00:00:00:00:00:02\n"), 2, true},
		{"invalid", strings.NewReader("10.0.0.1,00:00:00:00:00:01\n10.0.0.2,00:00:00:00:00:02\ninvalid"), 0, false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			ips, err := ReadPairs(d.data)
			if (err == nil && !d.ok) || (err != nil && d.ok) {
				t.Fatalf("unexpected result for data %v, expected ok: %v, got error: %v", d.data, d.ok, err)
			}
			if len(ips) != d.size {
				t.Fatalf("unexpected size for data %v, expected ok: %v, got: %v", d.data, d.size, len(ips))
			}
		})
	}
}

func Test_isValidIPv4(t *testing.T) {
	data := []struct {
		name string
		ip   string
		ok   bool
	}{
		{"ok", "10.0.0.1", true},
		{"invalid value", "10.0.1.300", false},
		{"ipv6", "2001:db8::/32", false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			isValid := isValidIPv4(d.ip)
			if isValid != d.ok {
				t.Fatalf("unexpected result for IP %v, expected ok: %v, got: %v", d.ip, d.ok, isValid)
			}
		})
	}
}

func Test_isValidMAC(t *testing.T) {
	data := []struct {
		name string
		mac  string
		ok   bool
	}{
		{"ok", "31:0c:8a:cb:8f:00", true},
		{"invalid value", "31:0c:8a:cb:8f:xd", false},
		{"truncated", "31:0c:8a:", false},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			isValid := isValidMAC(d.mac)
			if isValid != d.ok {
				t.Fatalf("unexpected result for MAC %v, expected ok: %v, got: %v", d.mac, d.ok, isValid)
			}
		})
	}
}
