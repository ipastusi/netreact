package main

type CacheKey [10]byte

type CacheValue struct {
	firstTs int64
	lastTs  int64
	count   int
}

type Cache struct {
	items map[CacheKey]CacheValue
}

func newCache() Cache {
	return Cache{
		items: map[CacheKey]CacheValue{},
	}
}

func (c *Cache) update(arpEvent ArpEvent) ExtendedArpEvent {
	key := c.generateCacheKey(arpEvent)

	val := c.items[key]
	if val.count == 0 {
		val.firstTs = arpEvent.ts
	}
	val.lastTs = arpEvent.ts
	val.count++
	c.items[key] = val

	return ExtendedArpEvent{
		ArpEvent:  arpEvent,
		firstTs:   val.firstTs,
		count:     val.count,
		eventType: ArpPacketReceived,
	}
}

func (c *Cache) get(arpEvent ArpEvent) CacheValue {
	key := c.generateCacheKey(arpEvent)
	return c.items[key]
}

func (c *Cache) generateCacheKey(arpEvent ArpEvent) CacheKey {
	var key CacheKey
	copy(key[:], arpEvent.ip)
	copy(key[4:], arpEvent.mac)
	return key
}
