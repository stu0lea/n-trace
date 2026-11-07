package main

import "errors"

var errAdminCancelled = errors.New("已取消管理员授权")

// adminRequest 是主进程交给提权子进程的任务描述。
type adminRequest struct {
	Task    string  `json:"task"`
	DataDir string  `json:"dataDir"`
	Args    *string `json:"args,omitempty"`
	DNSSet  bool    `json:"dnsSet,omitempty"`
	DNS     bool    `json:"dns,omitempty"`
	LogGB   float64 `json:"logGb,omitempty"`
}

type adminResult struct {
	OK       bool   `json:"ok"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
	ArgsText string `json:"argsText,omitempty"`
}
