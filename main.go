package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"
)

func main() {
	flags, err := getCliFlags()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	ifaceName := flags.ifaceName
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	logFileName := flags.logFileName
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var uiApp *UIApp = nil
	if flags.uiEnabled {
		uiApp = newUIApp()
		go func() {
			loadUI(uiApp, ifaceName)
		}()
	}

	maxSize := int32(64)
	promisc := flags.promiscMode
	pcapHandle, err := pcap.OpenLive(ifaceName, maxSize, promisc, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = pcapHandle.SetBPFFilter(flags.filter)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	command := flags.eventDir
	logHandler := slog.NewJSONHandler(logFile, nil)
	handler := newArpEventHandler(uiApp, logHandler, command)
	cache := newCache()
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
			processArpEvent(arpEvent, cache, handler)
		}
	}
}

func processArpEvent(arpEvent ArpEvent, cache Cache, handler ArpEventHandler) {
	extArpEvent := cache.update(arpEvent)
	handler.handle(extArpEvent)
}
