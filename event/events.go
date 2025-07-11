package event

import "net"

type ArpEvent struct {
	Ip  net.IP
	Mac net.HardwareAddr
	Ts  int64
}

type ExtendedArpEvent struct {
	ArpEvent
	FirstTs   int64
	Count     int
	MacVendor string
}

func (e ExtendedArpEvent) toPacketNotification(eventType Type, expectedCidrRange string, otherIps []string, otherMacs []string) Notification {
	return Notification{
		EventType:         eventType.describe(),
		Ip:                e.Ip.String(),
		Mac:               e.Mac.String(),
		FirstTs:           e.FirstTs,
		Ts:                e.Ts,
		Count:             e.Count,
		MacVendor:         e.MacVendor,
		ExpectedCidrRange: expectedCidrRange,
		OtherIps:          otherIps,
		OtherMacs:         otherMacs,
	}
}

func (e ExtendedArpEvent) toHostNotification(eventType Type, expectedCidrRange string, otherIps []string, otherMacs []string) Notification {
	return Notification{
		EventType:         eventType.describe(),
		Ip:                e.Ip.String(),
		Mac:               e.Mac.String(),
		Ts:                e.Ts,
		MacVendor:         e.MacVendor,
		ExpectedCidrRange: expectedCidrRange,
		OtherIps:          otherIps,
		OtherMacs:         otherMacs,
	}
}
