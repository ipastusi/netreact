package event

type Type int

const (
	NewPacket                 Type = 100
	NewLinkLocalUnicastPacket Type = 101
	NewUnspecifiedPacket      Type = 102
	NewBroadcastPacket        Type = 103
	NewUnexpectedIpPacket     Type = 104
	NewIpForMacPacket         Type = 105
	NewMacForIpPacket         Type = 106
	NewHost                   Type = 200
	NewLinkLocalUnicastHost   Type = 201
	NewUnspecifiedHost        Type = 202
	NewBroadcastHost          Type = 203
	NewUnexpectedIpHost       Type = 204
	NewIpForMacHost           Type = 205
	NewMacForIpHost           Type = 206
)

func (e Type) describe() string {
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
	case NewIpForMacPacket:
		return "NEW_IP_FOR_MAC_PACKET"
	case NewMacForIpPacket:
		return "NEW_MAC_FOR_IP_PACKET"
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
	case NewIpForMacHost:
		return "NEW_IP_FOR_MAC_HOST"
	case NewMacForIpHost:
		return "NEW_MAC_FOR_IP_HOST"
	default:
		return "UNKNOWN"
	}
}
