package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLiveCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := readLiveCheckpoint(dir); !os.IsNotExist(err) {
		t.Fatalf("首次启动应返回断点不存在，实际 err=%v", err)
	}

	writeLiveCheckpoint(dir, 248995)
	got, err := readLiveCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != 248995 {
		t.Fatalf("断点=%d，want 248995", got)
	}

	writeLiveCheckpoint(dir, 249301)
	got, err = readLiveCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != 249301 {
		t.Fatalf("覆盖后的断点=%d，want 249301", got)
	}
	if _, err := os.Stat(filepath.Join(dir, liveCheckpointName+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("临时断点文件应被重命名，实际 err=%v", err)
	}
}

func TestSelectLiveStart(t *testing.T) {
	cases := []struct {
		name       string
		checkpoint int64
		latest     int64
		want       int64
	}{
		{"有效断点", 248995, 249301, 248995},
		{"已经追平", 249301, 249301, 249301},
		{"首次启动", 0, 249301, 0},
		{"日志已轮转", 300000, 249301, 0},
		{"通道暂无事件", 248995, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectLiveStart(tc.checkpoint, tc.latest); got != tc.want {
				t.Fatalf("start=%d，want %d", got, tc.want)
			}
		})
	}
}
