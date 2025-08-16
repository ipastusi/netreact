package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type Flags struct {
	IfaceName         string
	Filter            string
	LogFileName       string
	StateFileName     string
	EventDir          string
	HostEventFilter   string
	PacketEventFilter string
	ExpectedCidrRange string
	ExcludeIPs        string
	ExcludeMACs       string
	ExcludePairs      string
	AutoCleanupDelay  uint
	PromiscMode       bool
	UiEnabled         bool
}

func GetFlags() (Flags, error) {
	eventDir := flag.String("d", "", "directory where to store the event files, relative to the working directory, if provided (default working directory)")
	filter := flag.String("f", "arp", "BPF filter, e.g. \"arp and src host not 0.0.0.0\"")
	packetEventFilter := flag.String("fp", "1111111", "packet event filter")
	hostEventFilter := flag.String("fh", "1111111", "host event filter")
	ifaceName := flag.String("i", "", "interface name, e.g. eth0")
	logFileName := flag.String("l", "netreact.log", "log file")
	promisc := flag.Bool("p", false, "put the interface in promiscuous mode (default false)")
	stateFileName := flag.String("s", "", "state file (default none)")
	ui := flag.Bool("u", true, "display textual user interface")
	expectedCidrRange := flag.String("c", "0.0.0.0/0", "expected CIDR range")
	excludeIPs := flag.String("ei", "", "file with excluded IP addresses")
	excludeMACs := flag.String("em", "", "file with excluded MAC addresses")
	excludePairs := flag.String("ep", "", "file with excluded IP-MAC address pairs")
	autoCleanupDelay := flag.Uint("a", 0, "auto cleanup generated event files after n seconds (default 0, disabled)")

	flag.Parse()
	flags := Flags{
		EventDir:          *eventDir,
		Filter:            *filter,
		PacketEventFilter: *packetEventFilter,
		HostEventFilter:   *hostEventFilter,
		IfaceName:         *ifaceName,
		LogFileName:       *logFileName,
		PromiscMode:       *promisc,
		StateFileName:     *stateFileName,
		UiEnabled:         *ui,
		ExpectedCidrRange: *expectedCidrRange,
		ExcludeIPs:        *excludeIPs,
		ExcludeMACs:       *excludeMACs,
		ExcludePairs:      *excludePairs,
		AutoCleanupDelay:  *autoCleanupDelay,
	}

	err := CheckFlags(flags)
	return flags, err
}

func CheckFlags(flags Flags) error {
	var pwd, absEventDirPath string
	if flags.IfaceName == "" {
		return fmt.Errorf("no interface name provided")
	} else if _, err := net.InterfaceByName(flags.IfaceName); err != nil {
		return err
	} else if pwd, err = os.Getwd(); err != nil {
		return err
	} else {
		evendDirPath := filepath.Join(pwd, flags.EventDir)
		absEventDirPath, err = filepath.Abs(evendDirPath)
		if err != nil {
			return err
		}
		// we might want to make it work on Windows one day. today is not that day
		if unix.Access(absEventDirPath, unix.W_OK) != nil {
			return fmt.Errorf("directory does not exist or is not writable: %v", absEventDirPath)
		}
		flags.EventDir = absEventDirPath
	}

	expectedEventFilterLen := 7
	if len(flags.PacketEventFilter) != expectedEventFilterLen {
		return fmt.Errorf("incorrect length of packet event filter: %v, expected: %v", len(flags.PacketEventFilter), expectedEventFilterLen)
	}
	for i, char := range flags.PacketEventFilter {
		if char != '0' && char != '1' {
			return fmt.Errorf("invalid packet event filter flag %v at position %v", char, i)
		}
	}

	if len(flags.HostEventFilter) != 7 {
		return fmt.Errorf("incorrect length of host event filter: %v", len(flags.HostEventFilter))
	}
	for i, char := range flags.HostEventFilter {
		if char != '0' && char != '1' {
			return fmt.Errorf("invalid host event filter flag %v at position %v", char, i)
		}
	}

	if ip, _, err := net.ParseCIDR(flags.ExpectedCidrRange); err != nil {
		return fmt.Errorf("invalid expected CIDR range %v: %v", flags.ExpectedCidrRange, err)
	} else if ip.To4() == nil {
		return fmt.Errorf("expected CIDR range should be IPv4, got: %v", ip)
	}

	excludeFiles := []string{flags.ExcludeIPs, flags.ExcludeMACs, flags.ExcludePairs}
	for _, excludeFile := range excludeFiles {
		if excludeFile != "" {
			if _, err := os.Stat(excludeFile); err != nil {
				return fmt.Errorf("file does not exist: %v", excludeFile)
			}
		}
	}

	return nil
}
