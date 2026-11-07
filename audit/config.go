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
}

func defaultAppConfig() appConfig {
	return appConfig{
		ReadIntervalSeconds: 5,
		LiveChannel:         defaultChannel,
		LogRetentionMonths:  6,
		SysmonLogMaxGB:      2,
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
`, c.ReadIntervalSeconds, c.LiveChannel, c.LogRetentionMonths, c.SysmonLogMaxGB)
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
}
