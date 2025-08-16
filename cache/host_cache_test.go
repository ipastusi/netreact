package cache_test

import (
	"net"
	"slices"
	"testing"

	"github.com/ipastusi/netreact/cache"
	"github.com/ipastusi/netreact/event"
	"github.com/ipastusi/netreact/state"
)

func Test_FromAppState(t *testing.T) {
	t.Parallel()

	appState := state.NewAppState()
	appState.Items = []state.Item{
		{
			Ip:      "10.0.0.1",
			Mac:     "00:00:00:01:02:03",
			FirstTs: 1749913040850,
			LastTs:  1749913040850,
			Count:   1,
		}, {
			Ip:      "10.0.0.2",
			Mac:     "00:00:00:04:05:06",
			FirstTs: 1749913040852,
			LastTs:  1749913040852,
			Count:   1,
		},
	}
	hostCache := cache.FromAppState(appState)

	hostKey := cache.KeyFromIpMac("10.0.0.1", "00:00:00:01:02:03")
	hostDetails, ok := hostCache.Items[hostKey]
	if !ok {
		t.Fatal("host not found")
	}
	expectedHostDetails := cache.HostDetails{
		FirstTs: 1749913040850,
		LastTs:  1749913040850,
		Count:   1,
	}
	if hostDetails != expectedHostDetails {
		t.Fatalf("unexpected host details, expected: %v, actual: %v", expectedHostDetails, hostDetails)
	}

	hostKey = cache.KeyFromIpMac("10.0.0.2", "00:00:00:04:05:06")
	hostDetails, ok = hostCache.Items[hostKey]
	if !ok {
		t.Fatal("host not found")
	}
	expectedHostDetails = cache.HostDetails{
		FirstTs: 1749913040852,
		LastTs:  1749913040852,
		Count:   1,
	}
	if hostDetails != expectedHostDetails {
		t.Fatalf("unexpected host details, expected: %v, actual: %v", expectedHostDetails, hostDetails)
	}
}

func Test_Update(t *testing.T) {
	t.Parallel()

	hostCache := cache.NewHostCache()

	// init host
	hostMacA, _ := net.ParseMAC("00:00:00:01:02:03")
	hostEventA1 := event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.1"),
		Mac: hostMacA,
		Ts:  1749913040850,
	}
	hostCache.Update(hostEventA1)

	// same host
	hostEventA2 := event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.1"),
		Mac: hostMacA,
		Ts:  1749913040851,
	}
	hostCache.Update(hostEventA2)

	// diff host
	hostMacB, _ := net.ParseMAC("00:00:00:04:05:06")
	hostEventB := event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.2"),
		Mac: hostMacB,
		Ts:  1749913040852,
	}
	hostCache.Update(hostEventB)

	hostCacheSize := len(hostCache.Items)
	if hostCacheSize != 2 {
		t.Fatal("unexpected host cache size:", hostCacheSize)
	}

	hostKeyA := cache.KeyFromIpMac("10.0.0.1", "00:00:00:01:02:03")
	hostDetailsA := hostCache.Items[hostKeyA]
	expectedHostDetailsA := cache.HostDetails{
		FirstTs: 1749913040850,
		LastTs:  1749913040851,
		Count:   2,
	}
	if hostDetailsA != expectedHostDetailsA {
		t.Fatalf("unexpected host details, expected: %v, actual: %v", expectedHostDetailsA, hostDetailsA)
	}

	hostKeyB := cache.KeyFromIpMac("10.0.0.2", "00:00:00:04:05:06")
	hostDetailsB := hostCache.Items[hostKeyB]
	expectedHostDetailsB := cache.HostDetails{
		FirstTs: 1749913040852,
		LastTs:  1749913040852,
		Count:   1,
	}
	if hostDetailsB != expectedHostDetailsB {
		t.Fatalf("unexpected host details, expected: %v, actual: %v", expectedHostDetailsB, hostDetailsB)
	}
}

func Test_ToAppState(t *testing.T) {
	t.Parallel()

	hostCache := cache.NewHostCache()

	hostKeyA := cache.KeyFromIpMac("10.0.0.1", "00:00:00:01:02:03")
	hostCache.Items[hostKeyA] = cache.HostDetails{
		FirstTs: 1749913040850,
		LastTs:  1749913040851,
		Count:   2,
	}

	hostKeyB := cache.KeyFromIpMac("10.0.0.2", "00:00:00:04:05:06")
	hostCache.Items[hostKeyB] = cache.HostDetails{
		FirstTs: 1749913040852,
		LastTs:  1749913040852,
		Count:   1,
	}

	appState := hostCache.ToAppState()

	appStateSize := len(appState.Items)
	if appStateSize != 2 {
		t.Fatal("unexpected app state size:", appStateSize)
	}

	expectedAppState := state.NewAppState()
	expectedAppState.Items = []state.Item{
		{
			Ip:      "10.0.0.1",
			Mac:     "00:00:00:01:02:03",
			FirstTs: 1749913040850,
			LastTs:  1749913040851,
			Count:   2,
		}, {
			Ip:      "10.0.0.2",
			Mac:     "00:00:00:04:05:06",
			FirstTs: 1749913040852,
			LastTs:  1749913040852,
			Count:   1,
		},
	}
	if !slices.Equal(appState.Items, expectedAppState.Items) {
		t.Fatalf("unexpected app state items, expected: %v, actual: %v", appState.Items, expectedAppState.Items)
	}
}

func Test_ToAppStateEmpty(t *testing.T) {
	t.Parallel()

	hostCache := cache.NewHostCache()
	appState := hostCache.ToAppState()
	if appState.Items == nil {
		t.Fatal("unexpected nil Items, should be empty")
	}
}

func Test_IpAndMacMaps(t *testing.T) {
	t.Parallel()

	hostCache := cache.NewHostCache()

	mac1, _ := net.ParseMAC("00:00:00:00:00:01")
	mac2, _ := net.ParseMAC("00:00:00:00:00:02")
	mac3, _ := net.ParseMAC("00:00:00:00:00:03")
	mac4, _ := net.ParseMAC("00:00:00:00:00:04")

	// 3 standard events
	e := event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.1"),
		Mac: mac1,
		Ts:  1749913040000,
	}
	hostCache.Update(e)

	e = event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.2"),
		Mac: mac2,
		Ts:  1749913040000,
	}
	hostCache.Update(e)

	e = event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.3"),
		Mac: mac3,
		Ts:  1749913040000,
	}
	hostCache.Update(e)

	// event with diff mac for already seen ip
	e = event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.2"),
		Mac: mac4,
		Ts:  1749913040000,
	}
	hostCache.Update(e)

	// event with diff ip for already seen mac
	e = event.ArpEvent{
		Ip:  net.ParseIP("10.0.0.5"),
		Mac: mac1,
		Ts:  1749913040000,
	}
	hostCache.Update(e)

	ipToMac, macToIp := hostCache.IpAndMacMaps()

	if size := len(ipToMac); size != 4 {
		t.Fatal("unexpected ipToMac size:", size)
	}
	if size := len(ipToMac["10.0.0.1"]); size != 1 {
		t.Fatal("unexpected size for 10.0.0.1", size)
	}
	if size := len(ipToMac["10.0.0.2"]); size != 2 {
		t.Fatal("unexpected size for 10.0.0.2", size)
	}
	if size := len(ipToMac["10.0.0.3"]); size != 1 {
		t.Fatal("unexpected size for 10.0.0.3", size)
	}
	if size := len(ipToMac["10.0.0.5"]); size != 1 {
		t.Fatal("unexpected size for 10.0.0.5", size)
	}

	if size := len(macToIp); size != 4 {
		t.Fatal("unexpected macToIp size:", size)
	}
	if size := len(macToIp[mac1.String()]); size != 2 {
		t.Fatalf("unexpected macToIp size for %v: %v", mac1.String(), size)
	}
	if size := len(macToIp[mac2.String()]); size != 1 {
		t.Fatalf("unexpected macToIp size for %v: %v", mac1.String(), size)
	}
	if size := len(macToIp[mac3.String()]); size != 1 {
		t.Fatalf("unexpected macToIp size for %v: %v", mac1.String(), size)
	}
	if size := len(macToIp[mac4.String()]); size != 1 {
		t.Fatalf("unexpected macToIp size for %v: %v", mac1.String(), size)
	}
}
