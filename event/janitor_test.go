package event

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func Test_newEventJanitor(t *testing.T) {
	now := time.Now().UnixMilli()
	nowPlus2Secs := now + 2000

	// should get removed by the janitor
	matchingFileName := fmt.Sprintf("../out/netreact-%v-100.json", now)
	err := os.WriteFile(matchingFileName, []byte(`{"match": true}`), 0644)
	if err != nil {
		t.Fatal("unexpected error creating a test file")
	}

	// should not get removed by the janitor
	notMatchingFileName := fmt.Sprintf("../out/netreact-%v-100.json", nowPlus2Secs)
	defer os.Remove(notMatchingFileName)
	err = os.WriteFile(notMatchingFileName, []byte(`{"match": false}`), 0644)
	if err != nil {
		t.Fatal("unexpected error creating a test file")
	}

	// cleanupEventFiles matching files
	delaySec := uint(2)
	janitor, err := NewEventJanitor(nil, "../out", delaySec)
	if err != nil {
		t.Fatal("unexpected error creating event janitor")
	}
	janitor.Start()
	time.Sleep(time.Duration(2500) * time.Millisecond)

	// assertions
	if _, err := os.Stat(matchingFileName); err == nil {
		t.Fatal("matching file not removed")
	}
	if _, err := os.Stat(notMatchingFileName); errors.Is(err, os.ErrNotExist) {
		t.Fatal("not matching file removed")
	}
}
