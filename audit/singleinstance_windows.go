//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const appWindowTitle = "N-trace 联网安全审计"

var (
	singletonMutex syscall.Handle

	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procCreateMutexW        = kernel32.NewProc("CreateMutexW")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
)

func acquireSingleInstance() bool {
	name, _ := syscall.UTF16PtrFromString(`Local\n-trace-UI-Singleton`)
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return true
	}
	if err == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		_ = syscall.CloseHandle(syscall.Handle(h))
		activateExistingWindow()
		return false
	}
	singletonMutex = syscall.Handle(h)
	return true
}

func activateExistingWindow() {
	title, _ := syscall.UTF16PtrFromString(appWindowTitle)
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, 9) // SW_RESTORE
	procSetForegroundWindow.Call(hwnd)
}
