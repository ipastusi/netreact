package main

import (
	"fmt"
	"net"
	"strings"
)

type ArpEventFilter struct {
	excludedIPs   map[string]bool
	excludedMACs  map[string]bool
	excludedPairs map[string]bool
}

func newArpEventFilter(excludedIPs map[string]bool, excludedMACs map[string]bool, excludedPairs map[string]bool) ArpEventFilter {
	return ArpEventFilter{
		excludedIPs:   excludedIPs,
		excludedMACs:  excludedMACs,
		excludedPairs: excludedPairs,
	}
}

func (f ArpEventFilter) isExcluded(ip string, mac string) bool {
	if f.excludedIPs[ip] {
		return true
	} else if f.excludedMACs[mac] {
		return true
	} else if pair := fmt.Sprintf("%v,%v", ip, mac); f.excludedPairs[pair] {
		return true
	}
	return false
}

func readIPs(data string) (map[string]bool, error) {
	ips := map[string]bool{}

	for line := range strings.Lines(data) {
		trimmedLine := strings.Trim(line, " ")
		trimmedLine = strings.TrimRight(trimmedLine, "\r\n")
		if !isValidIPv4(trimmedLine) {
			return nil, fmt.Errorf("invalid IP address: %v", line)
		}
		ips[trimmedLine] = true
	}

	return ips, nil
}

func readMACs(data string) (map[string]bool, error) {
	macs := map[string]bool{}

	for line := range strings.Lines(data) {
		trimmedLine := strings.Trim(line, " ")
		trimmedLine = strings.TrimRight(trimmedLine, "\r\n")
		if !isValidMAC(trimmedLine) {
			return nil, fmt.Errorf("invalid MAC address: %v", line)
		}
		macs[trimmedLine] = true
	}

	return macs, nil
}

func readPairs(data string) (map[string]bool, error) {
	pairs := map[string]bool{}

	for line := range strings.Lines(data) {
		trimmedLine := strings.Trim(line, " ")
		trimmedLine = strings.TrimRight(trimmedLine, "\r\n")
		parts := strings.Split(trimmedLine, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %v", line)
		}
		ip, mac := parts[0], parts[1]
		if !isValidIPv4(ip) {
			return nil, fmt.Errorf("invalid IP address: %v", line)
		} else if !isValidMAC(mac) {
			return nil, fmt.Errorf("invalid MAC address: %v", line)
		}
		pair := fmt.Sprintf("%v,%v", ip, mac)
		pairs[pair] = true
	}

	return pairs, nil
}

func isValidIPv4(ip string) bool {
	if addr := net.ParseIP(ip); addr == nil {
		return false
	} else if addr.To4() == nil {
		return false
	}
	return true
}

func isValidMAC(mac string) bool {
	// this could get improved
	_, err := net.ParseMAC(mac)
	if err != nil {
		return false
	}
	return true
}
