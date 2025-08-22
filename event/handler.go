package event

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ipastusi/netreact/config"
	"github.com/ipastusi/netreact/oui"
)

type ArpEventHandler struct {
	logHandler        slog.Handler
	eventDir          string
	packetEventConfig config.EventTypeConfig
	hostEventConfig   config.EventTypeConfig
	expectedCidrRange *net.IPNet
	ipToMac           map[string]map[string]struct{}
	macToIp           map[string]map[string]struct{}
}

func NewArpEventHandler(
	logHandler slog.Handler,
	eventDir string,
	packetEventConfig config.EventTypeConfig,
	hostEventConfig config.EventTypeConfig,
	expectedCidrRange string,
	ipToMac map[string]map[string]struct{},
	macToIp map[string]map[string]struct{}) ArpEventHandler {

	_, cidrRange, _ := net.ParseCIDR(expectedCidrRange)
	return ArpEventHandler{
		logHandler:        logHandler,
		eventDir:          eventDir,
		packetEventConfig: packetEventConfig,
		hostEventConfig:   hostEventConfig,
		expectedCidrRange: cidrRange,
		ipToMac:           ipToMac,
		macToIp:           macToIp,
	}
}

func (h ArpEventHandler) Handle(extArpEvent *ExtendedArpEvent) {
	h.handleLog(*extArpEvent)
	h.updateMaps(*extArpEvent)
	h.lookupMacVendor(extArpEvent)
	h.handleEventFiles(*extArpEvent)
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

func (h ArpEventHandler) lookupMacVendor(extArpEvent *ExtendedArpEvent) {
	extArpEvent.MacVendor = oui.MacToVendor(extArpEvent.Mac)
}

func (h ArpEventHandler) handleEventFiles(extArpEvent ExtendedArpEvent) {
	if *h.packetEventConfig.Any == true {
		h.handlePacketNotification(extArpEvent, NewPacket)
	}
	if *h.packetEventConfig.Any == true && extArpEvent.Count == 1 {
		h.handleHostNotification(extArpEvent, NewHost)
	}

	if extArpEvent.Ip.IsLinkLocalUnicast() {
		if *h.packetEventConfig.NewLinkLocalUnicast == true {
			h.handlePacketNotification(extArpEvent, NewLinkLocalUnicastPacket)
		}
		if *h.packetEventConfig.NewLinkLocalUnicast == true && extArpEvent.Count == 1 {
			h.handleHostNotification(extArpEvent, NewLinkLocalUnicastHost)
		}
	}

	if extArpEvent.Ip.IsUnspecified() {
		if *h.packetEventConfig.NewUnspecified == true {
			h.handlePacketNotification(extArpEvent, NewUnspecifiedPacket)
		}
		if *h.packetEventConfig.NewUnspecified == true && extArpEvent.Count == 1 {
			h.handleHostNotification(extArpEvent, NewUnspecifiedHost)
		}
	}

	if extArpEvent.Ip.Equal(net.IPv4bcast) {
		if *h.packetEventConfig.NewBroadcast == true {
			h.handlePacketNotification(extArpEvent, NewBroadcastPacket)
		}
		if *h.packetEventConfig.NewBroadcast == true && extArpEvent.Count == 1 {
			h.handleHostNotification(extArpEvent, NewBroadcastHost)
		}
	}

	// IP from unexpected CIDR range, but not in (169.254.0.0/16, 0.0.0.0, 255.255.255.255)
	if !h.expectedCidrRange.Contains(extArpEvent.Ip) &&
		!extArpEvent.Ip.IsLinkLocalUnicast() &&
		!extArpEvent.Ip.IsUnspecified() &&
		!extArpEvent.Ip.Equal(net.IPv4bcast) {
		if *h.packetEventConfig.NewUnexpected == true {
			h.handlePacketNotification(extArpEvent, NewUnexpectedIpPacket)
		}
		if *h.packetEventConfig.NewUnexpected == true && extArpEvent.Count == 1 {
			h.handleHostNotification(extArpEvent, NewUnexpectedIpHost)
		}
	}

	if len(h.macToIp[extArpEvent.Mac.String()]) > 1 {
		if *h.packetEventConfig.NewIpForMac == true {
			h.handlePacketNotification(extArpEvent, NewIpForMacPacket)
		}
		if *h.packetEventConfig.NewIpForMac == true {
			h.handleHostNotification(extArpEvent, NewIpForMacHost)
		}
	}

	if len(h.ipToMac[extArpEvent.Ip.String()]) > 1 {
		if *h.packetEventConfig.NewMacForIp == true {
			h.handlePacketNotification(extArpEvent, NewMacForIpPacket)
		}
		if *h.packetEventConfig.NewMacForIp == true {
			h.handleHostNotification(extArpEvent, NewMacForIpHost)
		}
	}
}

func (h ArpEventHandler) handlePacketNotification(extArpEvent ExtendedArpEvent, eventType Type) {
	expectedCidrRange := h.expectedCidrRange.String()
	otherIps, otherMacs := h.getOtherIps(extArpEvent), h.getOtherMacs(extArpEvent)
	eventJson := extArpEvent.toPacketNotification(eventType, expectedCidrRange, otherIps, otherMacs)
	h.storeNotification(eventJson, eventType)
}

func (h ArpEventHandler) handleHostNotification(extArpEvent ExtendedArpEvent, eventType Type) {
	expectedCidrRange := h.expectedCidrRange.String()
	otherIps, otherMacs := h.getOtherIps(extArpEvent), h.getOtherMacs(extArpEvent)
	eventJson := extArpEvent.toHostNotification(eventType, expectedCidrRange, otherIps, otherMacs)
	h.storeNotification(eventJson, eventType)
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

func (h ArpEventHandler) storeNotification(eventJson Notification, eventType Type) {
	eventFileName := fmt.Sprintf("netreact-%v-%v.json", eventJson.Ts, eventType)
	eventBytes, err := json.Marshal(eventJson)
	if err != nil {
		h.logError(err)
		return
	}
	eventFilePath := filepath.Join(h.eventDir, eventFileName)
	err = syncWriteToFile(eventFilePath, eventBytes)
	if err != nil {
		h.logError(err)
	}
}

func (h ArpEventHandler) logError(err error) {
	now := time.UnixMilli(time.Now().Unix())
	record := slog.NewRecord(now, slog.LevelError, err.Error(), 0)
	_ = h.logHandler.Handle(nil, record)
}

func syncWriteToFile(filename string, data []byte) error {
	// put extra effort into making sure the events are delivered without delay
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0644)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}
