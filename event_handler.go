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
	ArpPacketReceived EventType = iota
)

func (e EventType) describeEventType() string {
	switch e {
	case ArpPacketReceived:
		return "ARP_PACKET_RECEIVED"
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
	eventType EventType
	macVendor string
}

func (e ExtendedArpEvent) toEventJson() EventJson {
	return EventJson{
		EventType: e.eventType.describeEventType(),
		Ip:        e.ip.String(),
		Mac:       e.mac.String(),
		FirstTs:   e.firstTs,
		Ts:        e.ts,
		Count:     e.count,
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
	h.handleEventFile(extArpEvent)
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

func (h ArpEventHandler) handleEventFile(extArpEvent ExtendedArpEvent) {
	eventJson := extArpEvent.toEventJson()
	eventFileName := fmt.Sprintf("netreact-%v.json", eventJson.Ts)
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
	FirstTs   int64  `json:"firstTs"`
	Ts        int64  `json:"ts"`
	Count     int    `json:"count"`
	MacVendor string `json:"macVendor"`
}

func (h ArpEventHandler) logError(err error) {
	now := time.UnixMilli(time.Now().Unix())
	record := slog.NewRecord(now, slog.LevelError, err.Error(), 0)
	_ = h.logHandler.Handle(nil, record)
}
