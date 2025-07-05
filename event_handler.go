package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

// event type

type EventType int

const (
	NewPacket                 EventType = 100
	NewLinkLocalUnicastPacket EventType = 101
	NewUnspecifiedPacket      EventType = 102
	NewBroadcastPacket        EventType = 103
	NewUnexpectedIpPacket     EventType = 104
	NewHost                   EventType = 200
	NewLinkLocalUnicastHost   EventType = 201
	NewUnspecifiedHost        EventType = 202
	NewBroadcastHost          EventType = 203
	NewUnexpectedIpHost       EventType = 204
)

func (e EventType) describe() string {
	switch e {
	case NewPacket:
		return "NEW_PACKET"
	case NewLinkLocalUnicastPacket:
		return "NEW_LINK_LOCAL_UNICAST_PACKET"
	case NewUnspecifiedPacket:
		return "NEW_UNSPECIFIED_PACKET"
	case NewBroadcastPacket:
		return "NEW_BROADCAST_PACKET"
	case NewUnexpectedIpPacket:
		return "NEW_UNEXPECTED_IP_PACKET"
	case NewHost:
		return "NEW_HOST"
	case NewLinkLocalUnicastHost:
		return "NEW_LINK_LOCAL_UNICAST_HOST"
	case NewUnspecifiedHost:
		return "NEW_UNSPECIFIED_HOST"
	case NewBroadcastHost:
		return "NEW_BROADCAST_HOST"
	case NewUnexpectedIpHost:
		return "NEW_UNEXPECTED_IP_HOST"
	default:
		return "UNKNOWN"
	}
}

// arp event

type ArpEvent struct {
	ip  net.IP
	mac net.HardwareAddr
	ts  int64
}

// extended arp event

type ExtendedArpEvent struct {
	ArpEvent
	firstTs   int64
	count     int
	macVendor string
}

func (e ExtendedArpEvent) toNewPacketJson(eventType EventType, expectedCidrRange string) EventJson {
	return EventJson{
		EventType:         eventType.describe(),
		Ip:                e.ip.String(),
		Mac:               e.mac.String(),
		FirstTs:           e.firstTs,
		Ts:                e.ts,
		Count:             e.count,
		MacVendor:         e.macVendor,
		ExpectedCidrRange: expectedCidrRange,
	}
}

func (e ExtendedArpEvent) toNewHostJson(eventType EventType, expectedCidrRange string) EventJson {
	return EventJson{
		EventType:         eventType.describe(),
		Ip:                e.ip.String(),
		Mac:               e.mac.String(),
		Ts:                e.ts,
		MacVendor:         e.macVendor,
		ExpectedCidrRange: expectedCidrRange,
	}
}

// arp event handler

type ArpEventHandler struct {
	uiApp             *UIApp
	logHandler        slog.Handler
	eventDir          string
	packetEventFilter string
	hostEventFilter   string
	expectedCidrRange *net.IPNet
}

func newArpEventHandler(uiApp *UIApp, logHandler slog.Handler, eventDir string, packetEventFilter string, hostEventFilter string, expectedCidrRange string) ArpEventHandler {
	_, cidrRange, _ := net.ParseCIDR(expectedCidrRange)
	return ArpEventHandler{
		uiApp:             uiApp,
		logHandler:        logHandler,
		eventDir:          eventDir,
		packetEventFilter: packetEventFilter,
		hostEventFilter:   hostEventFilter,
		expectedCidrRange: cidrRange,
	}
}

func (h ArpEventHandler) handle(extArpEvent ExtendedArpEvent) {
	h.lookupMacVendor(&extArpEvent)
	h.handleUI(extArpEvent)
	h.handleLog(extArpEvent)
	h.handleEventFiles(extArpEvent)
}

func (h ArpEventHandler) lookupMacVendor(extArpEvent *ExtendedArpEvent) {
	(*extArpEvent).macVendor = macToVendor(extArpEvent.mac)
}

func (h ArpEventHandler) handleUI(extArpEvent ExtendedArpEvent) {
	if h.uiApp != nil {
		h.uiApp.upsertAndRefreshTable(extArpEvent)
	}
}

func (h ArpEventHandler) handleLog(extArpEvent ExtendedArpEvent) {
	if h.logHandler != nil {
		r := slog.NewRecord(time.UnixMilli(extArpEvent.ts), slog.LevelInfo, "ARP packet received", 0)
		r.AddAttrs(
			slog.String("IP", extArpEvent.ip.String()),
			slog.String("MAC", extArpEvent.mac.String()),
		)
		_ = h.logHandler.Handle(nil, r)
	}
}

func (h ArpEventHandler) handleEventFiles(extArpEvent ExtendedArpEvent) {
	if h.packetEventFilter[0] == '1' {
		h.handleNewPacketEventFile(extArpEvent, NewPacket)
	}
	if h.hostEventFilter[0] == '1' && extArpEvent.count == 1 {
		h.handleNewHostEventFile(extArpEvent, NewHost)
	}

	if extArpEvent.ip.IsLinkLocalUnicast() {
		if h.packetEventFilter[1] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewLinkLocalUnicastPacket)
		}
		if h.hostEventFilter[1] == '1' && extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewLinkLocalUnicastHost)
		}
	}

	if extArpEvent.ip.IsUnspecified() {
		if h.packetEventFilter[2] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewUnspecifiedPacket)
		}
		if h.hostEventFilter[2] == '1' && extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewUnspecifiedHost)
		}
	}

	if extArpEvent.ip.Equal(net.IPv4bcast) {
		if h.packetEventFilter[3] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewBroadcastPacket)
		}
		if h.hostEventFilter[3] == '1' && extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewBroadcastHost)
		}
	}

	// IP from unexpected CIDR range, but not in (169.254.0.0/16, 0.0.0.0, 255.255.255.255)
	if !h.expectedCidrRange.Contains(extArpEvent.ip) &&
		!extArpEvent.ip.IsLinkLocalUnicast() &&
		!extArpEvent.ip.IsUnspecified() &&
		!extArpEvent.ip.Equal(net.IPv4bcast) {
		if h.packetEventFilter[4] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewUnexpectedIpPacket)
		}
		if h.hostEventFilter[4] == '1' && extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewUnexpectedIpHost)
		}
	}
}

func (h ArpEventHandler) handleNewPacketEventFile(extArpEvent ExtendedArpEvent, eventType EventType) {
	expectedCidrRange := h.expectedCidrRange.String()
	eventJson := extArpEvent.toNewPacketJson(eventType, expectedCidrRange)
	h.storeEventFile(eventJson, eventType)
}

func (h ArpEventHandler) handleNewHostEventFile(extArpEvent ExtendedArpEvent, eventType EventType) {
	expectedCidrRange := h.expectedCidrRange.String()
	eventJson := extArpEvent.toNewHostJson(eventType, expectedCidrRange)
	h.storeEventFile(eventJson, eventType)
}

func (h ArpEventHandler) storeEventFile(eventJson EventJson, eventType EventType) {
	eventFileName := fmt.Sprintf("netreact-%v-%v.json", eventJson.Ts, eventType)
	eventBytes, err := json.Marshal(eventJson)
	if err != nil {
		h.logError(err)
		return
	}
	eventFilePath := filepath.Join(h.eventDir, eventFileName)
	err = os.WriteFile(eventFilePath, eventBytes, 0644)
	if err != nil {
		h.logError(err)
	}
}

func (h ArpEventHandler) logError(err error) {
	now := time.UnixMilli(time.Now().Unix())
	record := slog.NewRecord(now, slog.LevelError, err.Error(), 0)
	_ = h.logHandler.Handle(nil, record)
}

// event json

type EventJson struct {
	// IP and MAC addresses are stored as strings due to:
	// https://github.com/golang/go/issues/29678
	EventType         string `json:"eventType"`
	Ip                string `json:"ip"`
	Mac               string `json:"mac"`
	FirstTs           int64  `json:"firstTs,omitempty"`
	Ts                int64  `json:"ts"`
	Count             int    `json:"count,omitempty"`
	MacVendor         string `json:"macVendor"`
	ExpectedCidrRange string `json:"expectedCidrRange"`
}
