//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	swHide                = 0
	swShowNormal          = 1
)

var (
	shell32DLL          = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW = shell32DLL.NewProc("ShellExecuteExW")
)

// SHELLEXECUTEINFOW，字段顺序与 Win32 头文件一致。
type shellExecuteInfo struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         win.HWND
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	HInstApp     uintptr
	LpIDList     uintptr
	LpClass      *uint16
	HkeyClass    uintptr
	DwHotKey     uint32
	HIcon        uintptr
	HProcess     win.HPROCESS
}

func launchElevated(parent win.HWND, exe, params, workDir string, show int32) (win.HPROCESS, error) {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	p, err := syscall.UTF16PtrFromString(params)
	if err != nil {
		return 0, err
	}
	dir, err := syscall.UTF16PtrFromString(workDir)
	if err != nil {
		return 0, err
	}

	sei := shellExecuteInfo{
		CbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		FMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		Hwnd:         parent,
		LpVerb:       verb,
		LpFile:       file,
		LpParameters: p,
		LpDirectory:  dir,
		NShow:        show,
	}
	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == 1223 {
			return 0, errAdminCancelled
		}
		return 0, fmt.Errorf("请求管理员权限失败: %v", callErr)
	}
	if sei.HProcess == 0 {
		return 0, fmt.Errorf("管理员任务未启动")
	}
	return sei.HProcess, nil
}

func runElevatedProcess(parent win.HWND, exe, params, workDir string) (uint32, error) {
	hProcess, err := launchElevated(parent, exe, params, workDir, swHide)
	if err != nil {
		return 0, err
	}
	defer hProcess.CloseHandle()

	if _, err := hProcess.WaitForSingleObject(win.TimeoutInfinite()); err != nil {
		return 0, err
	}
	code, err := hProcess.GetExitCodeProcess()
	if err != nil {
		return 0, err
	}
	if co.ERROR(code) != co.ERROR_SUCCESS {
		return code, fmt.Errorf("管理员任务退出码 %d", code)
	}
	return code, nil
}

// startElevatedProcess 只负责拉起提权进程，不等待其退出。
func startElevatedProcess(parent win.HWND, exe, params, workDir string) error {
	hProcess, err := launchElevated(parent, exe, params, workDir, swShowNormal)
	if err != nil {
		return err
	}
	_ = hProcess.CloseHandle()
	return nil
}
