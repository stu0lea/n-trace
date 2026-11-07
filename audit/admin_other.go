//go:build !windows

package main

import "fmt"

func runAdminTaskFile(_, _ string) error {
	return fmt.Errorf("管理员任务仅支持 Windows")
}
