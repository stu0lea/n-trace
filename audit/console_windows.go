//go:build windows

package main

import (
	"os"

	"github.com/rodrigocfd/windigo/win"
)

// prepareWebConsole 让 GUI 子系统的 exe 在 Web 模式下也拥有可见控制台。
// 从现有终端启动时优先附加，否则创建新的控制台窗口。
func prepareWebConsole() {
	_ = win.FreeConsole()
	if err := win.AllocConsole(); err != nil {
		// 极少数宿主环境不允许新建控制台时，再尝试附着到父进程。
		if err := win.AttachConsole(-1); err != nil {
			return
		}
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
		os.Stdin = in
	}
	if out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
	_ = win.SetConsoleTitle("N-trace - Web")
}
