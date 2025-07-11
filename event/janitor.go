package event

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

type EventJanitor struct {
	logHandler slog.Handler
	pattern    string
	delaySec   uint
	ctx        context.Context
}

func NewEventJanitor(log slog.Handler, eventDir string, delaySec uint) (EventJanitor, error) {
	pattern := fmt.Sprintf("%v/netreact-?????????????-???.json", eventDir)
	if _, err := filepath.Glob(pattern); err != nil {
		return EventJanitor{}, err
	}

	// no cancel function here, as the only case this should shut down is when shutting down entire application
	ctx := context.Background()
	return EventJanitor{
		logHandler: log,
		pattern:    pattern,
		delaySec:   delaySec,
		ctx:        ctx,
	}, nil
}

func (j EventJanitor) Start() {
	go func() {
		for {
			<-time.After(time.Duration(j.delaySec) * time.Second)
			j.cleanupEventFiles()
		}
	}()
}

func (j EventJanitor) cleanupEventFiles() {
	files, _ := filepath.Glob(j.pattern)
	for _, file := range files {
		re := regexp.MustCompile("netreact-(?P<timestamp>[0-9]{13})-[0-9]{3}.json$")
		matches := re.FindStringSubmatch(file)

		if len(matches) == 0 {
			// file globbed but not matched by regex
			continue
		}

		timestampIdx := re.SubexpIndex("timestamp")
		timestampStr := matches[timestampIdx]
		timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)

		now := time.Now().UnixMilli()
		boundaryTimestamp := now - int64(j.delaySec)*1000
		if timestamp > boundaryTimestamp {
			// file is too fresh
			continue
		}

		if err := os.Remove(file); err != nil {
			logError(j.logHandler, err.Error())
		}
	}
}

func logError(log slog.Handler, msg string) {
	if log == nil {
		return
	}

	now := time.UnixMilli(time.Now().Unix())
	record := slog.NewRecord(now, slog.LevelError, msg, 0)
	_ = log.Handle(nil, record)
}
