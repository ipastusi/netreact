package cache

import (
	"net"
	"slices"

	"github.com/ipastusi/netreact/event"
	"github.com/ipastusi/netreact/state"
)

type HostCache struct {
	Items map[HostKey]HostDetails
}

func NewHostCache() HostCache {
	return HostCache{
		Items: map[HostKey]HostDetails{},
	}
}

func FromAppState(appState state.AppState) HostCache {
	cache := NewHostCache()
	for _, stateItem := range appState.Items {
		key := KeyFromIpMac(stateItem.Ip, stateItem.Mac)
		cache.Items[key] = HostDetails{
			FirstTs: stateItem.FirstTs,
			LastTs:  stateItem.LastTs,
			Count:   stateItem.Count,
		}
	}
	return cache
}

func (c *HostCache) ToAppState() state.AppState {
	appState := state.NewAppState()
	for cacheKey, cacheValue := range c.Items {
		ip, mac := cacheKey.ToIpMac()
		stateItem := state.Item{
			Ip:      ip,
			Mac:     mac,
			FirstTs: cacheValue.FirstTs,
			LastTs:  cacheValue.LastTs,
			Count:   cacheValue.Count,
		}
		appState.Items = append(appState.Items, stateItem)
	}
	slices.SortFunc(appState.Items, func(a, b state.Item) int {
		return int(a.FirstTs - b.FirstTs)
	})
	return appState
}

func (c *HostCache) IpAndMacMaps() (map[string]map[string]struct{}, map[string]map[string]struct{}) {
	ipToMac := map[string]map[string]struct{}{}
	macToIp := map[string]map[string]struct{}{}

	for key := range c.Items {
		ipBytes, macBytes := key.IpBytes(), key.MacBytes()
		ip := net.IP(ipBytes).String()
		mac := net.HardwareAddr(macBytes).String()

		if _, ok := ipToMac[ip]; !ok {
			ipToMac[ip] = map[string]struct{}{}
		}
		ipToMac[ip][mac] = struct{}{}

		if _, ok := macToIp[mac]; !ok {
			macToIp[mac] = map[string]struct{}{}
		}
		macToIp[mac][ip] = struct{}{}
	}

	return ipToMac, macToIp
}

func (c *HostCache) Update(arpEvent event.ArpEvent) event.ExtendedArpEvent {
	key := KeyFromArpEvent(arpEvent)

	val := c.Items[key]
	if val.Count == 0 {
		val.FirstTs = arpEvent.Ts
	}
	val.LastTs = arpEvent.Ts
	val.Count++
	c.Items[key] = val

	return event.ExtendedArpEvent{
		ArpEvent: arpEvent,
		FirstTs:  val.FirstTs,
		Count:    val.Count,
	}
}

func (c *HostCache) Host(key HostKey) HostDetails {
	return c.Items[key]
}
