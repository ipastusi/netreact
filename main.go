package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ipastusi/netreact/cache"
	"github.com/ipastusi/netreact/cli"
	"github.com/ipastusi/netreact/config"
	"github.com/ipastusi/netreact/event"
	"github.com/ipastusi/netreact/state"
)

func main() {
	flags := cli.GetFlags()
	var cfgData []byte
	var err error
	if flags.ConfigFileName != nil && *flags.ConfigFileName != "" {
		cfgData, err = os.ReadFile(*flags.ConfigFileName)
		if err != nil {
			exitOnError(err)
		}
	}

	cfg, err := config.GetConfig(cfgData, flags.IfaceName, flags.LogFileName, flags.PromiscMode, flags.StateFileName)
	if *flags.RenderConfig == true {
		renderedConfig, errMarshal := yaml.Marshal(cfg)
		fmt.Printf("%v", string(renderedConfig))
		var errs []error
		if err != nil {
			errs = append(errs, err)
		}
		if errMarshal != nil {
			errs = append(errs, err)
		}
		exitOnErrors(errs)
		os.Exit(0)
	}
	if err != nil && err.Error() == "no interface name provided" {
		fmt.Printf("Usage of %v:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	exitOnError(err)

	ifaceName := *cfg.IfaceName
	iface, err := net.InterfaceByName(ifaceName)
	exitOnError(err)

	logFileName := *cfg.LogFileName
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	exitOnError(err)

	maxSize := int32(64)
	promisc := *cfg.PromiscMode
	pcapHandle, err := pcap.OpenLive(ifaceName, maxSize, promisc, pcap.BlockForever)
	exitOnError(err)

	err = pcapHandle.SetBPFFilter(*cfg.BpfFilter)
	exitOnError(err)

	hostCache := cache.NewHostCache()
	if cfg.StateFileName != nil {
		var stateBytes []byte
		stateBytes, err = os.ReadFile(*cfg.StateFileName)
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
	if *cfg.Ui {
		uiApp = newUIApp(hostCache)
		go loadUI(uiApp, ifaceName, cfg.StateFileName)
	}

	if cfg.StateFileName != nil {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go handleSignals(sig, hostCache, *cfg.StateFileName)
	}

	closeFile := func(file *os.File) {
		closeErr := file.Close()
		if closeErr != nil {
			fmt.Println(closeErr)
		}
	}

	var excludeIPs, excludeMACs, excludePairs map[string]struct{}
	if cfg.EventsConfig.ExcludeConfig.IpFile != nil {
		ipFlagFile, err := os.Open(*cfg.EventsConfig.ExcludeConfig.IpFile)
		exitOnError(err)
		excludeIPs, err = event.ReadIPs(ipFlagFile)
		exitOnError(err)
		closeFile(ipFlagFile)
	}
	if cfg.EventsConfig.ExcludeConfig.MacFile != nil {
		macFlagFile, err := os.Open(*cfg.EventsConfig.ExcludeConfig.MacFile)
		exitOnError(err)
		excludeMACs, err = event.ReadMACs(macFlagFile)
		exitOnError(err)
		closeFile(macFlagFile)
	}
	if cfg.EventsConfig.ExcludeConfig.IpMacFile != nil {
		pairsFlagFile, err := os.Open(*cfg.EventsConfig.ExcludeConfig.IpMacFile)
		exitOnError(err)
		excludePairs, err = event.ReadPairs(pairsFlagFile)
		exitOnError(err)
		closeFile(pairsFlagFile)
	}

	logHandler := slog.NewJSONHandler(logFile, nil)
	eventDir := *cfg.EventsConfig.Directory
	autoCleanupDelay := *cfg.EventsConfig.AutoCleanupDelaySec
	if autoCleanupDelay > 0 {
		janitor, err := event.NewEventJanitor(logHandler, eventDir, autoCleanupDelay)
		exitOnError(err)
		janitor.Start()
	}

	filter := event.NewArpEventFilter(excludeIPs, excludeMACs, excludePairs)
	packetEventConfig := *cfg.EventsConfig.PacketEventConfig
	hostEventConfig := *cfg.EventsConfig.HostEventConfig
	expectedCidrRange := *cfg.EventsConfig.ExpectedCidrRange
	ipToMac, macToIp := hostCache.IpAndMacMaps()
	eventHandler := event.NewArpEventHandler(logHandler, eventDir, packetEventConfig, hostEventConfig, expectedCidrRange, ipToMac, macToIp)
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
