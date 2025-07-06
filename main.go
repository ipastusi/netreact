package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"
)

func main() {
	flags, err := getCliFlags()
	if err != nil && err.Error() == "no interface name provided" {
		fmt.Printf("Usage of %v:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	exitOnError(err)

	ifaceName := flags.ifaceName
	iface, err := net.InterfaceByName(ifaceName)
	exitOnError(err)

	logFileName := flags.logFileName
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	exitOnError(err)

	maxSize := int32(64)
	promisc := flags.promiscMode
	pcapHandle, err := pcap.OpenLive(ifaceName, maxSize, promisc, pcap.BlockForever)
	exitOnError(err)

	err = pcapHandle.SetBPFFilter(flags.filter)
	exitOnError(err)

	cache := newCache()
	stateFileName := flags.stateFileName
	if stateFileName != "" {
		var data []byte
		data, err = os.ReadFile(stateFileName)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			exitOnError(err)
		} else if err == nil {
			cache, err = cacheFromJson(data)
			exitOnError(err)
		}
	}

	var uiApp *UIApp = nil
	if flags.uiEnabled {
		uiApp = newUIApp(cache)
		go loadUI(uiApp, ifaceName, stateFileName)
	}

	if stateFileName != "" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go handleSignals(sig, cache, stateFileName)
	}

	var excludeIPs, excludeMACs, excludePairs map[string]bool
	if flags.excludeIPs != "" {
		data, err := os.ReadFile(flags.excludeIPs)
		exitOnError(err)
		excludeIPs, err = readIPs(string(data))
		exitOnError(err)
	}
	if flags.excludeMACs != "" {
		data, err := os.ReadFile(flags.excludeMACs)
		exitOnError(err)
		excludeMACs, err = readMACs(string(data))
		exitOnError(err)
	}
	if flags.excludePairs != "" {
		data, err := os.ReadFile(flags.excludePairs)
		exitOnError(err)
		excludePairs, err = readPairs(string(data))
		exitOnError(err)
	}
	filter := newArpEventFilter(excludeIPs, excludeMACs, excludePairs)

	command := flags.eventDir
	packetEventFilter := flags.packetEventFilter
	hostEventFilter := flags.hostEventFilter
	expectedCidrRange := flags.expectedCidrRange
	logHandler := slog.NewJSONHandler(logFile, nil)
	handler := newArpEventHandler(uiApp, logHandler, command, packetEventFilter, hostEventFilter, expectedCidrRange, cache)
	localMac := []byte(iface.HardwareAddr)
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			// if you are using a custom BPF filter and this is not an ARP packet
			continue
		}

		arp := arpLayer.(*layers.ARP)
		if !slices.Equal(arp.SourceHwAddress, localMac) {
			arpEvent := ArpEvent{
				ip:  net.IP(arp.SourceProtAddress),
				mac: net.HardwareAddr(arp.SourceHwAddress),
				ts:  time.Now().UnixMilli(),
			}
			processArpEvent(arpEvent, cache, filter, handler)
		}
	}
}

func exitOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func handleSignals(sig chan os.Signal, cache Cache, stateFileName string) {
	<-sig
	data, err := cache.toJson()
	exitOnError(err)

	err = os.WriteFile(stateFileName, data, 0644)
	exitOnError(err)
	os.Exit(0)
}

func processArpEvent(arpEvent ArpEvent, cache Cache, filter ArpEventFilter, handler ArpEventHandler) {
	if filter.isExcluded(arpEvent.ip.String(), arpEvent.mac.String()) {
		return
	}
	extArpEvent := cache.update(arpEvent)
	handler.handle(extArpEvent)
}
