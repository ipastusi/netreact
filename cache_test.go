package main

import (
	"bytes"
	"net"
	"testing"
)

func Test_cacheDeserUpdateSer(t *testing.T) {
	// deserializa
	inputJson := []byte("{\"items\":{\"0a000001f4ce23010203\":{\"firstTs\":1749913040850,\"lastTs\":1749913040850,\"count\":1}}}")
	cache, err := cacheFromJson(inputJson)
	if err != nil {
		t.Fatal("error deserializing input:", err)
	}

	// update same host
	sameHostMac, _ := net.ParseMAC("f4:ce:23:01:02:03")
	sameHostEvent := ArpEvent{
		ip:  net.ParseIP("10.0.0.1"),
		mac: sameHostMac,
		ts:  1749913040921,
	}
	cache.update(sameHostEvent)

	// add different host
	diffHostMac, _ := net.ParseMAC("f4:ce:23:04:05:06")
	diffHostEvent := ArpEvent{
		ip:  net.ParseIP("10.0.0.2"),
		mac: diffHostMac,
		ts:  1749913050760,
	}
	cache.update(diffHostEvent)

	// serialize
	expectedOutputJson := "{\"items\":{\"0a000001f4ce23010203\":{\"firstTs\":1749913040850,\"lastTs\":1749913040921,\"count\":2},\"0a000002f4ce23040506\":{\"firstTs\":1749913050760,\"lastTs\":1749913050760,\"count\":1}}}"
	actualOutputJsonBytes, err := cache.toJson()
	actualOutputJson := string(actualOutputJsonBytes)
	if err != nil {
		t.Fatal("error serializing input:", err)
	}
	if actualOutputJson != expectedOutputJson {
		t.Fatalf("incorrect output json, expected: \n%v\nactual: \n%v", expectedOutputJson, actualOutputJson)
	}

	// deserialize, serialize, compare if same
	otherCache, err := cacheFromJson(actualOutputJsonBytes)
	if err != nil {
		t.Fatal("error during deserialization")
	}
	yetAnotherActualOutputJsonBytes, err := otherCache.toJson()
	if err != nil {
		t.Fatal("error during serialization")
	}
	if !bytes.Equal(actualOutputJsonBytes, yetAnotherActualOutputJsonBytes) {
		t.Fatal("data change during deserialization / serialization")
	}
}

func Test_cacheDeserError(t *testing.T) {
	data := []struct {
		name  string
		input string
	}{
		{"Corrupted start", "\"items\":{\"0a000001f4ce23010203\":{\"firstTs\":1749913040850,\"lastTs\":1749913040850,\"count\":1}}}"},
		{"Corrupted end", "{\"items\":{\"0a000001f4ce23010203\":{\"firstTs\":1749913040850,\"lastTs\":1749913040850,\"count\":1"},
	}

	for _, d := range data {
		t.Run(d.name, func(t *testing.T) {
			inputJson := []byte(d.input)
			jsonOutput, err := cacheFromJson(inputJson)
			if err == nil {
				t.Fatal("no error deserializing illegal input:", jsonOutput)
			}
		})
	}
}
