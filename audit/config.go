package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type appConfig struct {
	ReadIntervalSeconds int
	LiveChannel         string
	LogRetentionMonths  int
	SysmonLogMaxGB      float64
	DataRetentionDays   int
	StoreRaw            bool
	SysmonArgs          string
	SysmonDNSEnabled    bool
}

func defaultAppConfig() appConfig {
	return appConfig{
		ReadIntervalSeconds: 5,
		LiveChannel:         defaultChannel,
		LogRetentionMonths:  6,
		SysmonLogMaxGB:      2,
		DataRetentionDays:   90,
		StoreRaw:            true,
		SysmonDNSEnabled:    true,
	}
}

func loadAppConfig(dir string) appConfig {
	cfg := defaultAppConfig()
	path := filepath.Join(dir, "config.ini")
	if b, err := os.ReadFile(path); err == nil {
		cfg.parse(string(b))
		_ = cfg.save(dir)
	} else if os.IsNotExist(err) {
		_ = cfg.save(dir)
	}
	cfg.normalize()
	return cfg
}

func (c *appConfig) parse(text string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		switch key {
		case "read_interval_seconds":
			if n, err := strconv.Atoi(val); err == nil {
				c.ReadIntervalSeconds = n
			}
		case "live_channel":
			c.LiveChannel = val
		case "log_retention_months":
			if n, err := strconv.Atoi(val); err == nil {
				c.LogRetentionMonths = n
			}
		case "sysmon_log_max_gb":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				c.SysmonLogMaxGB = v
			}
		case "data_retention_days":
			if n, err := strconv.Atoi(val); err == nil {
				c.DataRetentionDays = n
			}
		case "store_raw":
			if b, err := strconv.ParseBool(val); err == nil {
				c.StoreRaw = b
			}
		case "sysmon_args":
			c.SysmonArgs = strings.TrimSpace(val)
		case "sysmon_dns_enabled":
			if b, err := strconv.ParseBool(val); err == nil {
				c.SysmonDNSEnabled = b
			}
		}
	}
}

func (c appConfig) save(dir string) error {
	c.normalize()
	text := fmt.Sprintf(`# N-trace 配置
# 读取 Sysmon 日志与刷新表格的间隔（秒）
read_interval_seconds = %d
# Sysmon 日志通道
live_channel = %s
# 日志保留月数
log_retention_months = %d
# Sysmon 日志上限（GB）
sysmon_log_max_gb = %.1f
# 数据保留天数（超过后自动清理，0 表示不清理）
data_retention_days = %d
# 是否保存原始事件 JSON（关闭可显著减少磁盘占用，详情页将看不到原始事件）
store_raw = %t
# Sysmon 完整安装参数（可修改；DNS 配置路径由 DNS 开关自动增删）
sysmon_args = %s
# 是否启用 DNS 查询日志（Windows 8.1+）
sysmon_dns_enabled = %t
`, c.ReadIntervalSeconds, c.LiveChannel, c.LogRetentionMonths, c.SysmonLogMaxGB,
		c.DataRetentionDays, c.StoreRaw, c.SysmonArgs, c.SysmonDNSEnabled)
	return os.WriteFile(filepath.Join(dir, "config.ini"), []byte(text), 0o644)
}

func (c *appConfig) normalize() {
	if c.ReadIntervalSeconds < 1 || c.ReadIntervalSeconds > 3600 {
		c.ReadIntervalSeconds = 5
	}
	if c.LiveChannel == "" {
		c.LiveChannel = defaultChannel
	}
	if c.LogRetentionMonths < 1 || c.LogRetentionMonths > 120 {
		c.LogRetentionMonths = 6
	}
	if c.SysmonLogMaxGB < 0.0625 || c.SysmonLogMaxGB > 64 {
		c.SysmonLogMaxGB = 2
	}
	if c.DataRetentionDays < 0 || c.DataRetentionDays > 3650 {
		c.DataRetentionDays = 90
	}
}
