package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ipastusi/netreact/cache"
	"github.com/ipastusi/netreact/cli"
	"github.com/ipastusi/netreact/event"
	"github.com/ipastusi/netreact/state"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"
)

func main() {
	flags, err := cli.GetFlags()
	if err != nil && err.Error() == "no interface name provided" {
		fmt.Printf("Usage of %v:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	exitOnError(err)

	ifaceName := flags.IfaceName
	iface, err := net.InterfaceByName(ifaceName)
	exitOnError(err)

	logFileName := flags.LogFileName
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	exitOnError(err)

	maxSize := int32(64)
	promisc := flags.PromiscMode
	pcapHandle, err := pcap.OpenLive(ifaceName, maxSize, promisc, pcap.BlockForever)
	exitOnError(err)

	err = pcapHandle.SetBPFFilter(flags.Filter)
	exitOnError(err)

	hostCache := cache.NewHostCache()
	stateFileName := flags.StateFileName
	if stateFileName != "" {
		var stateBytes []byte
		stateBytes, err = os.ReadFile(stateFileName)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			exitOnError(err)
		} else if err == nil {
			errs := state.ValidateState(stateBytes)
			exitOnErrors(errs)
			appState, err := state.FromJson(stateBytes)
			exitOnError(err)
			hostCache = cache.FromAppState(appState)
		}
	}

	var uiApp *UIApp = nil
	if flags.UiEnabled {
		uiApp = newUIApp(hostCache)
		go loadUI(uiApp, ifaceName, stateFileName)
	}

	if stateFileName != "" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go handleSignals(sig, hostCache, stateFileName)
	}

	var excludeIPs, excludeMACs, excludePairs map[string]struct{}
	if flags.ExcludeIPs != "" {
		data, err := os.ReadFile(flags.ExcludeIPs)
		exitOnError(err)
		excludeIPs, err = event.ReadIPs(data)
		exitOnError(err)
	}
	if flags.ExcludeMACs != "" {
		data, err := os.ReadFile(flags.ExcludeMACs)
		exitOnError(err)
		excludeMACs, err = event.ReadMACs(data)
		exitOnError(err)
	}
	if flags.ExcludePairs != "" {
		data, err := os.ReadFile(flags.ExcludePairs)
		exitOnError(err)
		excludePairs, err = event.ReadPairs(data)
		exitOnError(err)
	}

	logHandler := slog.NewJSONHandler(logFile, nil)
	eventDir := flags.EventDir
	autoCleanupDelay := flags.AutoCleanupDelay
	if flags.AutoCleanupDelay > 0 {
		janitor, err := event.NewEventJanitor(logHandler, eventDir, autoCleanupDelay)
		exitOnError(err)
		janitor.Start()
	}

	filter := event.NewArpEventFilter(excludeIPs, excludeMACs, excludePairs)
	packetEventFilter := flags.PacketEventFilter
	hostEventFilter := flags.HostEventFilter
	expectedCidrRange := flags.ExpectedCidrRange
	ipToMac, macToIp := hostCache.IpAndMacMaps()
	eventHandler := event.NewArpEventHandler(logHandler, eventDir, packetEventFilter, hostEventFilter, expectedCidrRange, ipToMac, macToIp)
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
			arpEvent := event.ArpEvent{
				Ip:  net.IP(arp.SourceProtAddress),
				Mac: net.HardwareAddr(arp.SourceHwAddress),
				Ts:  time.Now().UnixMilli(),
			}
			processArpEvent(arpEvent, hostCache, filter, eventHandler, uiApp)
		}
	}
}

func exitOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func exitOnErrors(errs []error) {
	if len(errs) != 0 {
		fmt.Println(errs)
		os.Exit(1)
	}
}

func handleSignals(sig chan os.Signal, hostCache cache.HostCache, stateFileName string) {
	<-sig
	appState := hostCache.ToAppState()
	stateBytes, err := appState.ToJson()
	exitOnError(err)

	err = os.WriteFile(stateFileName, stateBytes, 0644)
	exitOnError(err)
	os.Exit(0)
}

func processArpEvent(arpEvent event.ArpEvent, hostCache cache.HostCache, filter event.ArpEventFilter, handler event.ArpEventHandler, uiApp *UIApp) {
	if filter.IsExcluded(arpEvent.Ip.String(), arpEvent.Mac.String()) {
		return
	}

	extArpEvent := hostCache.Update(arpEvent)
	handler.Handle(&extArpEvent)

	if uiApp != nil {
		uiApp.upsertAndRefreshTable(extArpEvent)
	}
}
