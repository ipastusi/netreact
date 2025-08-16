package state_test

import (
	"bytes"
	"testing"

	"github.com/ipastusi/netreact/state"
)

func Test_FromJson(t *testing.T) {
	t.Parallel()

	stateBytes := []byte(`{
		"items": [
    		{
				"ip": "10.0.0.1",
    			"mac": "00:00:00:01:02:03",
        		"firstTs": 1749913040850,
        		"lastTs": 1749913040851,
        		"count": 2
			}
    ]}`)
	appState, err := state.FromJson(stateBytes)
	if err != nil {
		t.Fatal("error deserializing input:", err)
	}

	stateSize := len(appState.Items)
	if stateSize != 1 {
		t.Fatal("unexpected number of items:", stateSize)
	}

	expectedItem := state.Item{
		Ip:      "10.0.0.1",
		Mac:     "00:00:00:01:02:03",
		FirstTs: 1749913040850,
		LastTs:  1749913040851,
		Count:   2,
	}
	if appState.Items[0] != expectedItem {
		t.Fatalf("incorrect deserialisation, expected: %v, actual: %v", expectedItem, appState.Items[0])
	}
}

func Test_ToJson(t *testing.T) {
	t.Parallel()

	appState := state.NewAppState()
	appState.Items = []state.Item{
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

	actualOutputJsonBytes, err := appState.ToJson()
	actualOutputJson := string(actualOutputJsonBytes)
	if err != nil {
		t.Fatal("error serializing input:", err)
	}

	expectedOutputJson := `{"items":[{"ip":"10.0.0.1","mac":"00:00:00:01:02:03","firstTs":1749913040850,"lastTs":1749913040851,"count":2},{"ip":"10.0.0.2","mac":"00:00:00:04:05:06","firstTs":1749913040852,"lastTs":1749913040852,"count":1}]}`
	if actualOutputJson != expectedOutputJson {
		t.Fatalf("incorrect output json, expected: \n%v\nactual: \n%v", expectedOutputJson, actualOutputJson)
	}
}

func Test_FromJsonToJson(t *testing.T) {
	t.Parallel()

	jsonInput := []byte(`{"items":[{"ip":"10.0.0.1","mac":"00:00:00:01:02:03","firstTs":1749913040850,"lastTs":1749913040851,"count":2},{"ip":"10.0.0.2","mac":"00:00:00:04:05:06","firstTs":1749913040852,"lastTs":1749913040852,"count":1}]}`)
	appState, err := state.FromJson(jsonInput)
	if err != nil {
		t.Fatal("error during deserialization")
	}

	jsonOutput, err := appState.ToJson()
	if err != nil {
		t.Fatal("error during serialization")
	}

	if !bytes.Equal(jsonInput, jsonOutput) {
		t.Fatalf("data change during deserialization / serialization - before: %v, after: %v", string(jsonInput), string(jsonOutput))
	}
}

func Test_ToJsonEmpty(t *testing.T) {
	t.Parallel()

	appState := state.NewAppState()
	outputJson, _ := appState.ToJson()
	if !bytes.Equal(outputJson, []byte(`{"items":[]}`)) {
		t.Fatal("unexpected outputJson:", string(outputJson))
	}
}

func Test_FromJsonError(t *testing.T) {
	t.Parallel()

	data := map[string]string{
		"Corrupted start": `
			"items": [
				{
					"ip": "10.0.0.1",
					"mac": "00:00:00:01:02:03",
					"firstTs": 1749913040850,
					"lastTs": 1749913040850,
					"count": 1
				}
			]
		}`,
		"Corrupted end": `{
			"items": [
				{
					"ip": "10.0.0.1",
					"mac": "00:00:00:01:02:03",
					"firstTs": 1749913040850,
					"lastTs": 1749913040850,
					"count": 1
				}`,
	}

	for name, d := range data {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inputJson := []byte(d)
			jsonOutput, err := state.FromJson(inputJson)
			if err == nil {
				t.Fatal("no error deserializing illegal input:", jsonOutput)
			}
		})
	}
}
