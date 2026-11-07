//go:build !windows

package main

import "fmt"

var errLiveUnsupported = fmt.Errorf("实时采集仅支持 Windows（其他平台请导入 .evtx）")

func liveSupported() error { return errLiveUnsupported }

func liveLatestID(channel string) (int64, error) { return 0, errLiveUnsupported }

func liveQuery(channel string, after int64, max int) ([]rawEvent, error) {
	return nil, errLiveUnsupported
}

func liveWarmup(channel string, max int) []rawEvent { return nil }
