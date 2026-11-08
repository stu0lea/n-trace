//go:build !windows

package main

import "fmt"

// SysmonStatus 供界面展示 Sysmon 安装状态与日志信息。
type SysmonStatus struct {
	Supported      bool   `json:"supported"`
	ServiceRunning bool   `json:"serviceRunning"`
	Error          string `json:"error,omitempty"`
}

func channelExists(channel string) bool { return false }

func sysmonServiceInstalled() bool { return false }

func sysmonLogFile() (string, int64) { return "", 0 }

func sysmonStatus(dataDir string) SysmonStatus {
	return SysmonStatus{Supported: false, Error: "仅 Windows 支持安装 Sysmon 与实时采集，其他平台请导入 .evtx"}
}

func sysmonSetDNS(dataDir string, on bool) error {
	return fmt.Errorf("仅 Windows 支持修改 DNS 开关")
}

func sysmonSetArgs(dataDir, text string) (string, error) {
	return "", fmt.Errorf("仅 Windows 支持修改安装参数")
}

func sysmonInstall(dataDir string) (string, error) {
	return "", fmt.Errorf("仅 Windows 支持安装 Sysmon")
}

func sysmonUninstall(dataDir string) (string, error) {
	return "", fmt.Errorf("仅 Windows 支持卸载 Sysmon")
}

func sysmonReinstall(dataDir string) (string, error) {
	return "", fmt.Errorf("仅 Windows 支持重新安装 Sysmon")
}

func sysmonSetLogSize(bytes int64) error {
	return fmt.Errorf("仅 Windows 支持修改日志大小")
}

func promptInstallSysmon(dataDir string) bool { return false }
