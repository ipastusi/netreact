package cache

import (
	"github.com/ipastusi/netreact/event"
	"net"
)

type HostKey [10]byte

func KeyFromArpEvent(arpEvent event.ArpEvent) HostKey {
	var key HostKey
	copy(key[:4], arpEvent.Ip.To4())
	copy(key[4:], arpEvent.Mac)
	return key
}

func keyFromIpMac(ip string, mac string) HostKey {
	keyBytes := net.ParseIP(ip).To4()
	macBytes, _ := net.ParseMAC(mac)
	keyBytes = append(keyBytes, macBytes...)
	return HostKey(keyBytes)
}

func (k HostKey) toIpMac() (string, string) {
	ipBytes, macBytes := k.IpBytes(), k.MacBytes()
	ip := net.IP(ipBytes).String()
	mac := net.HardwareAddr(macBytes).String()
	return ip, mac
}

func (k HostKey) IpBytes() []byte {
	return k[:4]
}

func (k HostKey) MacBytes() []byte {
	return k[4:]
}
