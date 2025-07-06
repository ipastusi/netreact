package main

import (
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"
)

type CliFlags struct {
	ifaceName         string
	filter            string
	logFileName       string
	stateFileName     string
	promiscMode       bool
	eventDir          string
	uiEnabled         bool
	hostEventFilter   string
	packetEventFilter string
	expectedCidrRange string
	excludeIPs        string
	excludeMACs       string
	excludePairs      string
}

func getCliFlags() (CliFlags, error) {
	eventDir := flag.String("d", "", "directory where to store the event files, relative to the working directory, if provided (default working directory)")
	filter := flag.String("f", "arp", "BPF filter, e.g. \"arp and src host not 0.0.0.0\"")
	packetEventFilter := flag.String("fp", "11111", "packet event filter")
	hostEventFilter := flag.String("fh", "11111", "host event filter")
	ifaceName := flag.String("i", "", "interface name, e.g. eth0")
	logFileName := flag.String("l", "netreact.log", "log file")
	promisc := flag.Bool("p", false, "put the interface in promiscuous mode (default false)")
	stateFileName := flag.String("s", "", "state file (default none)")
	ui := flag.Bool("u", true, "display textual user interface")
	expectedCidrRange := flag.String("c", "0.0.0.0/0", "expected CIDR range")
	excludeIPs := flag.String("ei", "", "file with excluded IP addresses")
	excludeMACs := flag.String("em", "", "file with excluded MAC addresses")
	excludePairs := flag.String("ep", "", "file with excluded IP-MAC address pairs")

	flag.Parse()
	flags := CliFlags{
		eventDir:          *eventDir,
		filter:            *filter,
		packetEventFilter: *packetEventFilter,
		hostEventFilter:   *hostEventFilter,
		ifaceName:         *ifaceName,
		logFileName:       *logFileName,
		promiscMode:       *promisc,
		stateFileName:     *stateFileName,
		uiEnabled:         *ui,
		expectedCidrRange: *expectedCidrRange,
		excludeIPs:        *excludeIPs,
		excludeMACs:       *excludeMACs,
		excludePairs:      *excludePairs,
	}

	err := processCliFlags(flags)
	return flags, err
}

func processCliFlags(flags CliFlags) error {
	var pwd, absEventDirPath string
	if flags.ifaceName == "" {
		return fmt.Errorf("no interface name provided")
	} else if _, err := net.InterfaceByName(flags.ifaceName); err != nil {
		return err
	} else if pwd, err = os.Getwd(); err != nil {
		return err
	} else {
		evendDirPath := filepath.Join(pwd, flags.eventDir)
		absEventDirPath, err = filepath.Abs(evendDirPath)
		if err != nil {
			return err
		}
		// we might want to make it work on Windows one day. today is not that day
		if unix.Access(absEventDirPath, unix.W_OK) != nil {
			return fmt.Errorf("directory does not exist or is not writable: %v", absEventDirPath)
		}
		flags.eventDir = absEventDirPath
	}

	if len(flags.packetEventFilter) != 5 {
		return fmt.Errorf("incorrect length of packet event filter: %v", len(flags.packetEventFilter))
	}
	for i, char := range flags.packetEventFilter {
		if char != '0' && char != '1' {
			return fmt.Errorf("invalid packet event filter flag %v at position %v", char, i)
		}
	}

	if len(flags.hostEventFilter) != 5 {
		return fmt.Errorf("incorrect length of host event filter: %v", len(flags.hostEventFilter))
	}
	for i, char := range flags.hostEventFilter {
		if char != '0' && char != '1' {
			return fmt.Errorf("invalid host event filter flag %v at position %v", char, i)
		}
	}

	if ip, _, err := net.ParseCIDR(flags.expectedCidrRange); err != nil {
		return fmt.Errorf("invalid expected CIDR range %v: %v", flags.expectedCidrRange, err)
	} else if ip.To4() == nil {
		return fmt.Errorf("expected CIDR range should be IPv4, got: %v", ip)
	}

	excludeFiles := []string{flags.excludeIPs, flags.excludeMACs, flags.excludePairs}
	for _, excludeFile := range excludeFiles {
		if excludeFile != "" {
			if _, err := os.Stat(excludeFile); err != nil {
				return fmt.Errorf("file does not exist: %v", excludeFile)
			}
		}
	}

	return nil
}
