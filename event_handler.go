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

type EventType int

const (
	NewPacket EventType = iota + 100
	NewLinkLocalUnicastPacket
	NewUnspecifiedPacket
	NewBroadcastPacket
	NewHost EventType = iota + 196
	NewLinkLocalUnicastHost
	NewUnspecifiedHost
	NewBroadcastHost
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
	case NewHost:
		return "NEW_HOST"
	case NewLinkLocalUnicastHost:
		return "NEW_LINK_LOCAL_UNICAST_HOST"
	case NewUnspecifiedHost:
		return "NEW_UNSPECIFIED_HOST"
	case NewBroadcastHost:
		return "NEW_BROADCAST_HOST"
	default:
		return "UNKNOWN"
	}
}

type ArpEvent struct {
	ip  net.IP
	mac net.HardwareAddr
	ts  int64
}

type ExtendedArpEvent struct {
	ArpEvent
	firstTs   int64
	count     int
	macVendor string
}

func (e ExtendedArpEvent) toNewPacketJson(eventType EventType) EventJson {
	return EventJson{
		EventType: eventType.describe(),
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		FirstTs:   e.firstTs,
		Ts:        e.ts,
		Count:     e.count,
		MacVendor: e.macVendor,
	}
}

func (e ExtendedArpEvent) toNewHostJson(eventType EventType) EventJson {
	return EventJson{
		EventType: eventType.describe(),
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		Ts:        e.ts,
		MacVendor: e.macVendor,
	}
}

type ArpEventHandler struct {
	uiApp      *UIApp
	logHandler slog.Handler
	eventDir   string
}

func newArpEventHandler(uiApp *UIApp, logHandler slog.Handler, eventDir string) ArpEventHandler {
	return ArpEventHandler{
		uiApp:      uiApp,
		logHandler: logHandler,
		eventDir:   eventDir,
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
	h.handleNewPacketEventFile(extArpEvent, NewPacket)
	if extArpEvent.count == 1 {
		h.handleNewHostEventFile(extArpEvent, NewHost)
	}

	if extArpEvent.ip.IsLinkLocalUnicast() {
		h.handleNewPacketEventFile(extArpEvent, NewLinkLocalUnicastPacket)
		if extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewLinkLocalUnicastHost)
		}
	}

	if extArpEvent.ip.IsUnspecified() {
		h.handleNewPacketEventFile(extArpEvent, NewUnspecifiedPacket)
		if extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewUnspecifiedHost)
		}
	}

	if extArpEvent.ip.Equal(net.IPv4bcast) {
		h.handleNewPacketEventFile(extArpEvent, NewBroadcastPacket)
		if extArpEvent.count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewBroadcastHost)
		}
	}
}

func (h ArpEventHandler) handleNewPacketEventFile(extArpEvent ExtendedArpEvent, eventType EventType) {
	eventJson := extArpEvent.toNewPacketJson(eventType)
	h.storeEventFile(eventJson, eventType)
}

func (h ArpEventHandler) handleNewHostEventFile(extArpEvent ExtendedArpEvent, eventType EventType) {
	eventJson := extArpEvent.toNewHostJson(eventType)
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

type EventJson struct {
	// IP and MAC addresses are stored as strings due to:
	// https://github.com/golang/go/issues/29678
	EventType string `json:"eventType"`
	Ip        string `json:"ip"`
	Mac       string `json:"mac"`
	FirstTs   int64  `json:"firstTs,omitempty"`
	Ts        int64  `json:"ts"`
	Count     int    `json:"count,omitempty"`
	MacVendor string `json:"macVendor"`
}

func (h ArpEventHandler) logError(err error) {
	now := time.UnixMilli(time.Now().Unix())
	record := slog.NewRecord(now, slog.LevelError, err.Error(), 0)
	_ = h.logHandler.Handle(nil, record)
}
