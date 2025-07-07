package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
)

// cache key

type CacheKey [10]byte

func (k CacheKey) MarshalText() ([]byte, error) {
	keyByteArray := k[:]
	keyHex := hex.EncodeToString(keyByteArray)
	return []byte(keyHex), nil
}

func (k *CacheKey) UnmarshalText(input []byte) error {
	s := string(input)
	keyByteSlice, err := hex.DecodeString(s)
	if err == nil {
		*k = CacheKey(keyByteSlice)
	}
	return err
}

// cache value

type CacheValue struct {
	FirstTs int64 `json:"firstTs"`
	LastTs  int64 `json:"lastTs"`
	Count   int   `json:"count"`
}

// cache

type Cache struct {
	Items map[CacheKey]CacheValue `json:"items"`
}

func newCache() Cache {
	return Cache{
		Items: map[CacheKey]CacheValue{},
	}
}

func cacheFromJson(data []byte) (Cache, error) {
	cache := newCache()
	err := json.Unmarshal(data, &cache)
	return cache, err
}

func (c *Cache) getIpAndMacMaps() (map[string]map[string]struct{}, map[string]map[string]struct{}) {
	ipToMac := map[string]map[string]struct{}{}
	macToIp := map[string]map[string]struct{}{}

	for key := range c.Items {
		ipBytes, macBytes := key[:4], key[4:]
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

func (c *Cache) toJson() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Cache) update(arpEvent ArpEvent) ExtendedArpEvent {
	key := c.generateCacheKey(arpEvent)

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
	key := c.generateCacheKey(arpEvent)
	return c.Items[key]
}

func (c *Cache) generateCacheKey(arpEvent ArpEvent) CacheKey {
	var key CacheKey
	copy(key[:], arpEvent.ip.To4())
	copy(key[4:], arpEvent.mac)
	return key
}
