package event

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func Test_newEventJanitor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test")
	}

	nowMillis := time.Now().UnixMilli()
	nowPlus2Secs := nowMillis + 2000

	// should get removed by the janitor
	matchingFileName := fmt.Sprintf("../out/netreact-%v-100.json", nowMillis)
	err := os.WriteFile(matchingFileName, []byte(`{"match": true}`), 0644)
	if err != nil {
		t.Fatal("unexpected error creating a test file")
	}

	// should not get removed by the janitor
	notMatchingFileName := fmt.Sprintf("../out/netreact-%v-100.json", nowPlus2Secs)
	defer func() {
		err = os.Remove(notMatchingFileName)
		if err != nil {
			fmt.Println(err)
		}
	}()

	err = os.WriteFile(notMatchingFileName, []byte(`{"match": false}`), 0644)
	if err != nil {
		t.Fatal("unexpected error creating a test file")
	}

	// CleanupEventFiles matching files
	delaySec := uint(1)
	janitor, err := NewEventJanitor(nil, "../out", delaySec)
	if err != nil {
		t.Fatal("unexpected error creating event janitor")
	}

	janitor.Start()

	time.Sleep(time.Duration(100) * time.Millisecond)
	if _, err := os.Stat(matchingFileName); err != nil {
		t.Fatal("matching file removed too quickly")
	}

	assertThat(t, func() bool {
		_, err := os.Stat(matchingFileName)
		return err != nil
	}, 20, 100*time.Millisecond, "matching file not removed")

	if _, err := os.Stat(notMatchingFileName); err != nil {
		t.Fatal("not matching file removed")
	}
}

func assertThat(t *testing.T, assert func() bool, maxRetries int, waitTime time.Duration, message string) {
	for i := 0; i < maxRetries; i++ {
		if assert() {
			return
		}
		time.Sleep(waitTime)
	}
	t.Fatal(message)
}
