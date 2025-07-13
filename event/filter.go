package event

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

type ArpEventFilter struct {
	excludedIPs   map[string]struct{}
	excludedMACs  map[string]struct{}
	excludedPairs map[string]struct{}
}

func NewArpEventFilter(excludedIPs map[string]struct{}, excludedMACs map[string]struct{}, excludedPairs map[string]struct{}) ArpEventFilter {
	return ArpEventFilter{
		excludedIPs:   excludedIPs,
		excludedMACs:  excludedMACs,
		excludedPairs: excludedPairs,
	}
}

func (f ArpEventFilter) IsExcluded(ip string, mac string) bool {
	pair := fmt.Sprintf("%v,%v", ip, mac)
	if _, ok := f.excludedIPs[ip]; ok {
		return true
	} else if _, ok = f.excludedMACs[mac]; ok {
		return true
	} else if _, ok = f.excludedPairs[pair]; ok {
		return true
	}
	return false
}

func ReadIPs(reader io.Reader) (map[string]struct{}, error) {
	ips := map[string]struct{}{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.Trim(line, " ")
		trimmedLine = strings.TrimRight(trimmedLine, "\r\n")
		if !isValidIPv4(trimmedLine) {
			return nil, fmt.Errorf("invalid IP address: %v", line)
		}
		ips[trimmedLine] = struct{}{}
	}

	return ips, nil
}

func ReadMACs(reader io.Reader) (map[string]struct{}, error) {
	macs := map[string]struct{}{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.Trim(line, " ")
		trimmedLine = strings.TrimRight(trimmedLine, "\r\n")
		if !isValidMAC(trimmedLine) {
			return nil, fmt.Errorf("invalid MAC address: %v", line)
		}
		macs[trimmedLine] = struct{}{}
	}

	return macs, nil
}

func ReadPairs(reader io.Reader) (map[string]struct{}, error) {
	pairs := map[string]struct{}{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
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
		pairs[pair] = struct{}{}
	}

	return pairs, nil
}

func isValidIPv4(ip string) bool {
	if addr := net.ParseIP(ip); addr == nil || addr.To4() == nil {
		return false
	}
	return true
}

func isValidMAC(mac string) bool {
	if _, err := net.ParseMAC(mac); err != nil {
		return false
	}
	return true
}
