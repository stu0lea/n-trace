//go:build windows

package main

import "testing"

func TestLiveTransportIconsAreCreated(t *testing.T) {
	for _, pause := range []bool{false, true} {
		icon, err := makeLiveTransportIcon(pause, 16)
		if err != nil {
			t.Fatalf("pause=%v: %v", pause, err)
		}
		if icon == 0 {
			t.Fatalf("pause=%v: 图标句柄为空", pause)
		}
		_ = icon.DestroyIcon()
	}
}
