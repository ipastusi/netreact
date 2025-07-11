package event

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

type ArpEventHandler struct {
	logHandler        slog.Handler
	eventDir          string
	packetEventFilter string
	hostEventFilter   string
	expectedCidrRange *net.IPNet
	ipToMac           map[string]map[string]struct{}
	macToIp           map[string]map[string]struct{}
}

func NewArpEventHandler(
	logHandler slog.Handler,
	eventDir string,
	packetEventFilter string,
	hostEventFilter string,
	expectedCidrRange string,
	ipToMac map[string]map[string]struct{},
	macToIp map[string]map[string]struct{}) ArpEventHandler {

	_, cidrRange, _ := net.ParseCIDR(expectedCidrRange)
	return ArpEventHandler{
		logHandler:        logHandler,
		eventDir:          eventDir,
		packetEventFilter: packetEventFilter,
		hostEventFilter:   hostEventFilter,
		expectedCidrRange: cidrRange,
		ipToMac:           ipToMac,
		macToIp:           macToIp,
	}
}

func (h ArpEventHandler) Handle(extArpEvent ExtendedArpEvent) {
	h.updateMaps(extArpEvent)
	h.handleLog(extArpEvent)
	h.handleEventFiles(extArpEvent)
}

func (h ArpEventHandler) updateMaps(extArpEvent ExtendedArpEvent) {
	ip, mac := extArpEvent.Ip.String(), extArpEvent.Mac.String()

	if _, ok := h.ipToMac[ip]; !ok {
		h.ipToMac[ip] = map[string]struct{}{}
	}
	h.ipToMac[ip][mac] = struct{}{}

	if _, ok := h.macToIp[mac]; !ok {
		h.macToIp[mac] = map[string]struct{}{}
	}
	h.macToIp[mac][ip] = struct{}{}
}

func (h ArpEventHandler) handleLog(extArpEvent ExtendedArpEvent) {
	if h.logHandler != nil {
		r := slog.NewRecord(time.UnixMilli(extArpEvent.Ts), slog.LevelInfo, "ARP packet received", 0)
		r.AddAttrs(
			slog.String("IP", extArpEvent.Ip.String()),
			slog.String("MAC", extArpEvent.Mac.String()),
		)
		_ = h.logHandler.Handle(nil, r)
	}
}

func (h ArpEventHandler) handleEventFiles(extArpEvent ExtendedArpEvent) {
	if h.packetEventFilter[0] == '1' {
		h.handleNewPacketEventFile(extArpEvent, NewPacket)
	}
	if h.hostEventFilter[0] == '1' && extArpEvent.Count == 1 {
		h.handleNewHostEventFile(extArpEvent, NewHost)
	}

	if extArpEvent.Ip.IsLinkLocalUnicast() {
		if h.packetEventFilter[1] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewLinkLocalUnicastPacket)
		}
		if h.hostEventFilter[1] == '1' && extArpEvent.Count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewLinkLocalUnicastHost)
		}
	}

	if extArpEvent.Ip.IsUnspecified() {
		if h.packetEventFilter[2] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewUnspecifiedPacket)
		}
		if h.hostEventFilter[2] == '1' && extArpEvent.Count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewUnspecifiedHost)
		}
	}

	if extArpEvent.Ip.Equal(net.IPv4bcast) {
		if h.packetEventFilter[3] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewBroadcastPacket)
		}
		if h.hostEventFilter[3] == '1' && extArpEvent.Count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewBroadcastHost)
		}
	}

	// IP from unexpected CIDR range, but not in (169.254.0.0/16, 0.0.0.0, 255.255.255.255)
	if !h.expectedCidrRange.Contains(extArpEvent.Ip) &&
		!extArpEvent.Ip.IsLinkLocalUnicast() &&
		!extArpEvent.Ip.IsUnspecified() &&
		!extArpEvent.Ip.Equal(net.IPv4bcast) {
		if h.packetEventFilter[4] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewUnexpectedIpPacket)
		}
		if h.hostEventFilter[4] == '1' && extArpEvent.Count == 1 {
			h.handleNewHostEventFile(extArpEvent, NewUnexpectedIpHost)
		}
	}

	if len(h.macToIp[extArpEvent.Mac.String()]) > 1 {
		if h.packetEventFilter[5] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewIpForMacPacket)
		}
		if h.hostEventFilter[5] == '1' {
			h.handleNewHostEventFile(extArpEvent, NewIpForMacHost)
		}
	}

	if len(h.ipToMac[extArpEvent.Ip.String()]) > 1 {
		if h.packetEventFilter[6] == '1' {
			h.handleNewPacketEventFile(extArpEvent, NewMacForIpPacket)
		}
		if h.hostEventFilter[6] == '1' {
			h.handleNewHostEventFile(extArpEvent, NewMacForIpHost)
		}
	}
}

func (h ArpEventHandler) handleNewPacketEventFile(extArpEvent ExtendedArpEvent, eventType Type) {
	expectedCidrRange := h.expectedCidrRange.String()
	otherIps, otherMacs := h.getOtherIps(extArpEvent), h.getOtherMacs(extArpEvent)
	eventJson := extArpEvent.toPacketNotification(eventType, expectedCidrRange, otherIps, otherMacs)
	h.storeEventFile(eventJson, eventType)
}

func (h ArpEventHandler) handleNewHostEventFile(extArpEvent ExtendedArpEvent, eventType Type) {
	expectedCidrRange := h.expectedCidrRange.String()
	otherIps, otherMacs := h.getOtherIps(extArpEvent), h.getOtherMacs(extArpEvent)
	eventJson := extArpEvent.toHostNotification(eventType, expectedCidrRange, otherIps, otherMacs)
	h.storeEventFile(eventJson, eventType)
}

func (h ArpEventHandler) getOtherIps(extArpEvent ExtendedArpEvent) []string {
	all := h.macToIp[extArpEvent.Mac.String()]
	var other []string
	for ip := range all {
		if ip != extArpEvent.Ip.String() {
			other = append(other, ip)
		}
	}
	return other
}

func (h ArpEventHandler) getOtherMacs(extArpEvent ExtendedArpEvent) []string {
	all := h.ipToMac[extArpEvent.Ip.String()]
	var other []string
	for mac := range all {
		if mac != extArpEvent.Mac.String() {
			other = append(other, mac)
		}
	}
	return other
}

func (h ArpEventHandler) storeEventFile(eventJson Notification, eventType Type) {
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
