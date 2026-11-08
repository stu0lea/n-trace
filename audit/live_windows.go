//go:build windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// 实时采集看 Sysmon 的进程创建、进程退出、网络连接、DNS 查询四类事件。
const liveEventFilter = `*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22)]]`

func liveSupported() error { return nil }

// runWevt 调用 wevtutil 并返回标准输出；失败时带回错误信息。
func runWevt(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wevtutil", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(decodeWinText(errb.Bytes()))
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), fmt.Errorf("%s", msg)
	}
	return out.Bytes(), nil
}

// liveLatestID 读取通道里最新一条相关事件的记录号，作为采集起点。
func liveLatestID(channel string) (int64, error) {
	b, err := runWevt("qe", channel, "/q:"+liveEventFilter, "/f:xml", "/rd:true", "/c:1")
	if err != nil {
		return 0, err
	}
	evs := parseXMLEvents(b)
	if len(evs) == 0 {
		return 0, nil
	}
	rec, _ := strconv.ParseInt(evs[0].Rec, 10, 64)
	return rec, nil
}

// liveQuery 取记录号大于 after 的事件（最多 max 条）。XPath 带记录号过滤失败时回退到最新 max 条。
func liveQuery(channel string, after int64, max int) ([]rawEvent, error) {
	q := fmt.Sprintf(`*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22) and EventRecordID>%d]]`, after)
	if b, err := runWevt("qe", channel, "/q:"+q, "/f:xml", "/c:"+strconv.Itoa(max)); err == nil {
		return parseXMLEvents(b), nil
	}
	b, err := runWevt("qe", channel, "/q:"+liveEventFilter, "/f:xml", "/rd:true", "/c:"+strconv.Itoa(max))
	if err != nil {
		return nil, err
	}
	return parseXMLEvents(b), nil
}

// liveQueryAfter 按记录号从小到大读取历史事件，用于启动时补读。
func liveQueryAfter(channel string, after int64, max int) ([]rawEvent, error) {
	q := fmt.Sprintf(`*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=22) and EventRecordID>%d]]`, after)
	b, err := runWevt("qe", channel, "/q:"+q, "/f:xml", "/c:"+strconv.Itoa(max))
	if err != nil {
		return nil, err
	}
	evs := parseXMLEvents(b)
	appPrintf("补读查询：after=%d bytes=%d events=%d", after, len(b), len(evs))
	return evs, nil
}

// liveWarmup 读取最近的进程创建与 DNS 事件，用于补齐进程命令行和域名关联。
func liveWarmup(channel string, max int) []rawEvent {
	b, err := runWevt("qe", channel, "/q:*[System[(EventID=1 or EventID=22)]]", "/f:xml", "/rd:true", "/c:"+strconv.Itoa(max))
	if err != nil {
		return nil
	}
	return parseXMLEvents(b)
}
