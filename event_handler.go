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

func (e ExtendedArpEvent) toNewArpPacketJson() EventJson {
	return EventJson{
		EventType: "NEW_ARP_PACKET",
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		FirstTs:   e.firstTs,
		Ts:        e.ts,
		Count:     e.count,
		MacVendor: e.macVendor,
	}
}

func (e ExtendedArpEvent) toNewHostJson() EventJson {
	return EventJson{
		EventType: "NEW_HOST",
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		Ts:        e.ts,
		MacVendor: e.macVendor,
	}
}

func (e ExtendedArpEvent) toNewLinkLocalUnicastHostJson() EventJson {
	return EventJson{
		EventType: "NEW_LINK_LOCAL_UNICAST_HOST",
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		Ts:        e.ts,
		MacVendor: e.macVendor,
	}
}

func (e ExtendedArpEvent) toNewUnspecifiedHostJson() EventJson {
	return EventJson{
		EventType: "NEW_UNSPECIFIED_HOST",
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		Ts:        e.ts,
		MacVendor: e.macVendor,
	}
}

func (e ExtendedArpEvent) toNewBroadcastHostJson() EventJson {
	return EventJson{
		EventType: "NEW_BROADCAST_HOST",
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
	h.handleArpPacketEventFile(extArpEvent)

	if extArpEvent.count == 1 {
		h.handleNewHostEventFile(extArpEvent)
	}

	if extArpEvent.ip.IsLinkLocalUnicast() && extArpEvent.count == 1 {
		h.handleNewLinkLocalUnicastHostEventFile(extArpEvent)
	}

	if extArpEvent.ip.IsUnspecified() && extArpEvent.count == 1 {
		h.handleNewUnspecifiedHostEventFile(extArpEvent)
	}

	if extArpEvent.ip.Equal(net.IPv4bcast) && extArpEvent.count == 1 {
		h.handleNewBroadcastHostEventFile(extArpEvent)
	}
}

func (h ArpEventHandler) handleArpPacketEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toNewArpPacketJson()
	h.storeEventFile(eventJson, 0)
}

func (h ArpEventHandler) handleNewHostEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toNewHostJson()
	h.storeEventFile(eventJson, 1)
}

func (h ArpEventHandler) handleNewLinkLocalUnicastHostEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toNewLinkLocalUnicastHostJson()
	h.storeEventFile(eventJson, 2)
}

func (h ArpEventHandler) handleNewUnspecifiedHostEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toNewUnspecifiedHostJson()
	h.storeEventFile(eventJson, 3)
}

func (h ArpEventHandler) handleNewBroadcastHostEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toNewBroadcastHostJson()
	h.storeEventFile(eventJson, 4)
}

func (h ArpEventHandler) storeEventFile(eventJson EventJson, eventCode int) {
	eventFileName := fmt.Sprintf("netreact-%v-%v.json", eventJson.Ts, eventCode)
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
