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
	ifaceName   string
	filter      string
	logFileName string
	promiscMode bool
	eventDir    string
	uiEnabled   bool
}

func getCliFlags() (CliFlags, error) {
	eventDir := flag.String("d", "", "directory where to store the event files, relative to the working directory, if provided (default working directory)")
	filter := flag.String("f", "arp", "custom BPF filter, e.g. \"arp and src host not 0.0.0.0\"")
	ifaceName := flag.String("i", "", "interface name, e.g. eth0")
	logFileName := flag.String("l", "netreact.log", "log file")
	promisc := flag.Bool("p", false, "put the interface in promiscuous mode")
	ui := flag.Bool("u", true, "display textual user interface")

	flag.Parse()
	flags := CliFlags{
		ifaceName:   *ifaceName,
		filter:      *filter,
		logFileName: *logFileName,
		promiscMode: *promisc,
		eventDir:    *eventDir,
		uiEnabled:   *ui,
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
	return nil
}
