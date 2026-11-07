package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	appOut     io.Writer = os.Stdout
	appLogMu   sync.Mutex
	appLogPath string
)

type monthlyLog struct {
	mu           sync.Mutex
	path         string
	file         *os.File
	month        string
	retainMonths int
}

func newMonthlyLog(path string, retainMonths int) (*monthlyLog, error) {
	if retainMonths <= 0 {
		retainMonths = 6
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	month := time.Now().Format("2006-01")
	if !fi.ModTime().IsZero() && fi.ModTime().Format("2006-01") != month {
		f.Close()
		archiveMonthly(path, fi.ModTime().Format("2006-01"))
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
	}
	cleanupMonthly(filepath.Dir(path), retainMonths)
	return &monthlyLog{path: path, file: f, month: month, retainMonths: retainMonths}, nil
}

func (w *monthlyLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if now := time.Now().Format("2006-01"); now != w.month {
		_ = w.file.Close()
		archiveMonthly(w.path, w.month)
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			w.file = nil
			return 0, err
		}
		w.file = f
		w.month = now
		cleanupMonthly(filepath.Dir(w.path), w.retainMonths)
	}
	return w.file.Write(p)
}

func archiveMonthly(path, month string) {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return
	}
	target := filepath.Join(filepath.Dir(path), "trace-audit-"+month+".log")
	if _, err := os.Stat(target); err == nil {
		src, err := os.Open(path)
		if err != nil {
			return
		}
		defer src.Close()
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		_, _ = io.Copy(dst, src)
		dst.Close()
		_ = os.Remove(path)
		return
	}
	_ = os.Rename(path, target)
}

func cleanupMonthly(dir string, retainMonths int) {
	if retainMonths <= 0 {
		retainMonths = 6
	}
	cutoff := time.Now().AddDate(0, -retainMonths, 0)
	files, _ := filepath.Glob(filepath.Join(dir, "trace-audit-????-??.log"))
	for _, file := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(file), "trace-audit-"), ".log")
		t, err := time.Parse("2006-01", name)
		if err == nil && t.Before(cutoff) {
			_ = os.Remove(file)
		}
	}
}

// setupAppLog 把应用输出同时写到数据目录的日志文件；GUI 子系统下没有控制台，
// 文件是唯一的运行记录。当前日志固定写 trace-audit.log，跨月自动归档为
// trace-audit-YYYY-MM.log，只保留最近 6 个月。
func setupAppLog(dir string, retainMonths int) {
	appLogPath = filepath.Join(dir, "trace-audit.log")
	f, err := newMonthlyLog(appLogPath, retainMonths)
	if err != nil {
		appOut = os.Stdout
		return
	}
	// 文件写在前面：GUI 子系统里 stdout 无效也不会影响文件落盘。
	appOut = io.MultiWriter(f, os.Stdout)
	log.SetOutput(appOut)
	log.SetFlags(log.LstdFlags)
	appPrintf("===== N-trace %s 启动 =====", version)
}

func appPrintf(format string, args ...interface{}) {
	writeAppLog(fmt.Sprintf(format, args...))
}

func appPrintln(args ...interface{}) {
	writeAppLog(fmt.Sprintln(args...))
}

func appPrint(args ...interface{}) {
	writeAppLog(fmt.Sprint(args...))
}

func writeAppLog(s string) {
	s = strings.TrimRight(s, "\r\n")
	if s == "" {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString(ts)
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	appLogMu.Lock()
	_, _ = io.WriteString(appOut, b.String())
	appLogMu.Unlock()
}
