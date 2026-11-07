//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runAdminTaskFile(reqPath, resPath string) error {
	data, err := os.ReadFile(reqPath)
	if err != nil {
		return fmt.Errorf("读取管理员任务失败: %w", err)
	}
	var req adminRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("解析管理员任务失败: %w", err)
	}
	res := performAdminTask(req)
	if resPath != "" {
		if b, err := json.Marshal(res); err == nil {
			_ = os.WriteFile(resPath, b, 0o644)
		}
	}
	if !res.OK {
		return fmt.Errorf("%s", res.Error)
	}
	return nil
}

func performAdminTask(req adminRequest) adminResult {
	fail := func(err error) adminResult {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		appPrintf("管理员任务失败：%s", msg)
		return adminResult{OK: false, Error: msg}
	}
	if strings.TrimSpace(req.DataDir) == "" {
		return fail(fmt.Errorf("数据目录为空"))
	}

	switch req.Task {
	case "install":
		argsText := ""
		if req.Args != nil {
			text, err := sysmonSetArgs(req.DataDir, *req.Args)
			if err != nil {
				return fail(err)
			}
			argsText = text
		}
		if req.DNSSet {
			if err := sysmonSetDNS(req.DataDir, req.DNS); err != nil {
				return fail(err)
			}
		}
		out, err := sysmonInstall(req.DataDir)
		if err != nil {
			res := fail(err)
			res.Output = out
			res.ArgsText = argsText
			return res
		}
		res := adminResult{OK: true, Output: out, ArgsText: argsText}
		appPrintf("管理员任务完成：安装 Sysmon")
		return res

	case "uninstall":
		out, err := sysmonUninstall(req.DataDir)
		if err != nil {
			res := fail(err)
			res.Output = out
			return res
		}
		appPrintf("管理员任务完成：卸载 Sysmon")
		return adminResult{OK: true, Output: out}

	case "logsize":
		if req.LogGB <= 0 {
			return fail(fmt.Errorf("日志上限无效"))
		}
		if err := sysmonSetLogSize(int64(req.LogGB * float64(int64(1)<<30))); err != nil {
			return fail(err)
		}
		appPrintf("管理员任务完成：日志上限 %.1f GB", req.LogGB)
		return adminResult{OK: true, Output: fmt.Sprintf("日志上限已设为 %.1f GB。", req.LogGB)}
	}
	return fail(fmt.Errorf("未知管理员任务：%s", req.Task))
}

// runAdminTask 在已是管理员时直接执行，否则通过 UAC 启动同程序的临时任务进程。
func (a *nativeApp) runAdminTask(req adminRequest) (adminResult, error) {
	req.DataDir = a.cfg.dataDir
	if isAdmin() {
		res := performAdminTask(req)
		if !res.OK {
			return res, fmt.Errorf("%s", res.Error)
		}
		return res, nil
	}

	dir, err := os.MkdirTemp("", "n-trace-admin-")
	if err != nil {
		return adminResult{}, err
	}
	defer os.RemoveAll(dir)
	reqPath := filepath.Join(dir, "request.json")
	resPath := filepath.Join(dir, "result.json")
	payload, err := json.Marshal(req)
	if err != nil {
		return adminResult{}, err
	}
	if err := os.WriteFile(reqPath, payload, 0o600); err != nil {
		return adminResult{}, err
	}

	exe, err := os.Executable()
	if err != nil {
		return adminResult{}, err
	}
	params := fmt.Sprintf(`-data %s -admin-task %s -admin-result %s`,
		quoteWinArg(a.cfg.dataDir), quoteWinArg(reqPath), quoteWinArg(resPath))
	if _, err := runElevatedProcess(a.wnd.Hwnd(), exe, params, a.cfg.dataDir); err != nil {
		return adminResult{}, err
	}

	data, err := os.ReadFile(resPath)
	if err != nil {
		return adminResult{}, fmt.Errorf("管理员任务没有返回结果: %w", err)
	}
	var res adminResult
	if err := json.Unmarshal(data, &res); err != nil {
		return adminResult{}, err
	}
	if !res.OK {
		return res, fmt.Errorf("%s", res.Error)
	}
	return res, nil
}

func quoteWinArg(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
