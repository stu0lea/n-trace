//go:build !windows

package main

import "fmt"

func nativeRun(_ nativeConfig) error {
	return fmt.Errorf("原生界面仅支持 Windows")
}
