package state

import (
	"encoding/json"
)

type AppState struct {
	Items []Item `json:"items"`
}

type Item struct {
	Ip      string `json:"ip"`
	Mac     string `json:"mac"`
	FirstTs int64  `json:"firstTs"`
	LastTs  int64  `json:"lastTs"`
	Count   int    `json:"count"`
}

func NewAppState() AppState {
	return AppState{
		// nil vs empty slice matters when marshalling to json
		Items: make([]Item, 0),
	}
}

func FromJson(data []byte) (AppState, error) {
	var appState AppState
	err := json.Unmarshal(data, &appState)
	return appState, err
}

func (s *AppState) ToJson() ([]byte, error) {
	return json.Marshal(s)
}
