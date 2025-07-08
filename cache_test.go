package main

import (
	"bytes"
	"net"
	"testing"
)

func Test_cacheDeserUpdateSer(t *testing.T) {
	// deserialize
	inputJson := []byte(`{
		"items": [
    		{
				"ip": "10.0.0.1",
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1749913040850,
        		"lastTs": 1749913040850,
        		"count": 1
			}
    ]}`)
	cache, err := fromJson(inputJson)
	if err != nil {
		t.Fatal("error deserializing input:", err)
	}

	// update same host
	sameHostMac, _ := net.ParseMAC("00:00:00:01:02:03")
	sameHostEvent := ArpEvent{
		ip:  net.ParseIP("10.0.0.1"),
		mac: sameHostMac,
		ts:  1749913040851,
	}
	cache.update(sameHostEvent)

	// add different host
	diffHostMac, _ := net.ParseMAC("00:00:00:04:05:06")
	diffHostEvent := ArpEvent{
		ip:  net.ParseIP("10.0.0.2"),
		mac: diffHostMac,
		ts:  1749913040852,
	}
	cache.update(diffHostEvent)

	// serialize
	expectedOutputJson := `{"items":[{"ip":"10.0.0.1","mac":"00:00:00:01:02:03","firstTs":1749913040850,"lastTs":1749913040851,"count":2},{"ip":"10.0.0.2","mac":"00:00:00:04:05:06","firstTs":1749913040852,"lastTs":1749913040852,"count":1}]}`
	actualOutputJsonBytes, err := cache.toJson()
	actualOutputJson := string(actualOutputJsonBytes)
	if err != nil {
		t.Fatal("error serializing input:", err)
	}
	if actualOutputJson != expectedOutputJson {
		t.Fatalf("incorrect output json, expected: \n%v\nactual: \n%v", expectedOutputJson, actualOutputJson)
	}

	// deserialize, serialize, compare if same
	otherCache, err := fromJson(actualOutputJsonBytes)
	if err != nil {
		t.Fatal("error during deserialization")
	}
	yetAnotherActualOutputJsonBytes, err := otherCache.toJson()
	if err != nil {
		t.Fatal("error during serialization")
	}
	if !bytes.Equal(actualOutputJsonBytes, yetAnotherActualOutputJsonBytes) {
		t.Fatalf("data change during deserialization / serialization - before: %v, after: %v", string(actualOutputJsonBytes), string(yetAnotherActualOutputJsonBytes))
	}
}

func Test_cacheDeserError(t *testing.T) {
	data := []struct {
		name  string
		input string
	}{
		{"Corrupted start", `
			"items": [
				{
					"ip": "10.0.0.1",
					"mac": "00:00:00:01:02:03",
					"firstTs": 1749913040850,
					"lastTs": 1749913040850,
					"count": 1
				}
			]
		}`},
		{"Corrupted end", `{
			"items": [
				{
					"ip": "10.0.0.1",
					"mac": "00:00:00:01:02:03",
					"firstTs": 1749913040850,
					"lastTs": 1749913040850,
					"count": 1
				}`},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			inputJson := []byte(d.input)
			jsonOutput, err := fromJson(inputJson)
			if err == nil {
				t.Fatal("no error deserializing illegal input:", jsonOutput)
			}
		})
	}
}

func Test_getIpAndMacMaps(t *testing.T) {
	cache := newCache()

	mac1, _ := net.ParseMAC("00:00:00:00:00:01")
	mac2, _ := net.ParseMAC("00:00:00:00:00:02")
	mac3, _ := net.ParseMAC("00:00:00:00:00:03")
	mac4, _ := net.ParseMAC("00:00:00:00:00:04")

	// 3 standard events
	event := ArpEvent{
		ip:  net.ParseIP("10.0.0.1"),
		mac: mac1,
		ts:  1749913040000,
	}
	cache.update(event)

	event = ArpEvent{
		ip:  net.ParseIP("10.0.0.2"),
		mac: mac2,
		ts:  1749913040000,
	}
	cache.update(event)

	event = ArpEvent{
		ip:  net.ParseIP("10.0.0.3"),
		mac: mac3,
		ts:  1749913040000,
	}
	cache.update(event)

	// event with diff mac for already seen ip
	event = ArpEvent{
		ip:  net.ParseIP("10.0.0.2"),
		mac: mac4,
		ts:  1749913040000,
	}
	cache.update(event)

	// event with diff ip for already seen mac
	event = ArpEvent{
		ip:  net.ParseIP("10.0.0.5"),
		mac: mac1,
		ts:  1749913040000,
	}
	cache.update(event)

	ipToMac, macToIp := cache.getIpAndMacMaps()

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
