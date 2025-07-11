package main

import (
	"encoding/json"
	"net"
	"slices"
)

// cache key

type CacheKey [10]byte

func cacheKeyFromArpEvent(arpEvent ArpEvent) CacheKey {
	var key CacheKey
	copy(key[:4], arpEvent.ip.To4())
	copy(key[4:], arpEvent.mac)
	return key
}

func cacheKeyFromIpMac(ip string, mac string) CacheKey {
	keyBytes := net.ParseIP(ip).To4()
	macBytes, _ := net.ParseMAC(mac)
	keyBytes = append(keyBytes, macBytes...)
	return CacheKey(keyBytes)
}

func (k CacheKey) toIpMac() (string, string) {
	ipBytes, macBytes := k.ipBytes(), k.macBytes()
	ip := net.IP(ipBytes).String()
	mac := net.HardwareAddr(macBytes).String()
	return ip, mac
}

func (k CacheKey) ipBytes() []byte {
	return k[:4]
}

func (k CacheKey) macBytes() []byte {
	return k[4:]
}

// cache value

type CacheValue struct {
	FirstTs int64 `json:"firstTs"`
	LastTs  int64 `json:"lastTs"`
	Count   int   `json:"count"`
}

// cache

type Cache struct {
	Items map[CacheKey]CacheValue
}

func newCache() Cache {
	return Cache{
		Items: map[CacheKey]CacheValue{},
	}
}

// state file

type State struct {
	Items []StateItem `json:"items"`
}

func newState() State {
	return State{
		// nil vs empty slice matters when marshalling to json
		Items: make([]StateItem, 0),
	}
}

type StateItem struct {
	Ip  string `json:"ip"`
	Mac string `json:"mac"`
	CacheValue
}

func fromJson(data []byte) (Cache, error) {
	var state State
	err := json.Unmarshal(data, &state)
	cache := newCache()
	for _, stateItem := range state.Items {
		key := cacheKeyFromIpMac(stateItem.Ip, stateItem.Mac)
		cache.Items[key] = CacheValue{
			FirstTs: stateItem.FirstTs,
			LastTs:  stateItem.LastTs,
			Count:   stateItem.Count,
		}
	}
	return cache, err
}

func (c *Cache) toJson() ([]byte, error) {
	state := newState()
	for cacheKey, cacheValue := range c.Items {
		ip, mac := cacheKey.toIpMac()
		stateItem := StateItem{
			Ip:         ip,
			Mac:        mac,
			CacheValue: cacheValue,
		}
		state.Items = append(state.Items, stateItem)
	}
	slices.SortFunc(state.Items, func(a, b StateItem) int {
		return int(a.FirstTs - b.FirstTs)
	})
	return json.Marshal(state)
}

func (c *Cache) getIpAndMacMaps() (map[string]map[string]struct{}, map[string]map[string]struct{}) {
	ipToMac := map[string]map[string]struct{}{}
	macToIp := map[string]map[string]struct{}{}

	for key := range c.Items {
		ipBytes, macBytes := key.ipBytes(), key.macBytes()
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

func (c *Cache) update(arpEvent ArpEvent) ExtendedArpEvent {
	key := cacheKeyFromArpEvent(arpEvent)

	val := c.Items[key]
	if val.Count == 0 {
		val.FirstTs = arpEvent.ts
	}
	val.LastTs = arpEvent.ts
	val.Count++
	c.Items[key] = val

	return ExtendedArpEvent{
		ArpEvent: arpEvent,
		firstTs:  val.FirstTs,
		count:    val.Count,
	}
}

func (c *Cache) get(arpEvent ArpEvent) CacheValue {
	key := cacheKeyFromArpEvent(arpEvent)
	return c.Items[key]
}
