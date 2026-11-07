//go:build windows

package main

import (
	"sort"
	"strings"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

func showSyntaxHelp(a *nativeApp) {
	fields := a.fields
	tab := 0
	if a.tabs != nil {
		tab = a.tabs.active
		fields = a.activeFields()
	}
	rows := syntaxHelpRows(tab, fields)
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("语法规则 - "+syntaxTabLabel(tab)).
		Size(ui.Dpi(920, 700)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	lv := ui.NewListView(modal, ui.OptsListView().
		Position(ui.Dpi(12, 12)).
		Size(ui.Dpi(880, 596)).
		CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS|co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("分类", ui.DpiX(90)).
		Column("语法 / 字段", ui.DpiX(260)).
		Column("说明", ui.DpiX(520)))

	ui.NewStatic(modal, ui.OptsStatic().
		Text("双击规则可追加到语法输入框；字段行只追加字段前缀。值含空格时用双引号括起来。").
		Position(ui.Dpi(12, 616)).
		Size(ui.Dpi(700, 20)))

	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(802, 630)).
		Width(ui.DpiX(90)))

	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	lv.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(rows) {
			a.appendSyntax(rows[p.IItem][3])
		}
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	modal.On().WmCreate(func(_ ui.WmCreate) int {
		for _, row := range rows {
			lv.AddItem(row[0], row[1], row[2])
		}
		return 0
	})
	modal.ShowModal()
}

func syntaxTabLabel(tab int) string {
	switch tab {
	case 1:
		return "进程"
	case 2:
		return "DNS"
	default:
		return "连接"
	}
}

func syntaxHelpRows(tab int, fields []FieldMeta) [][4]string {
	rows := syntaxRulesForTab(tab)
	typeNames := map[string]string{
		"text": "文本", "int": "数值", "bool": "布尔", "time": "时间",
	}
	for _, f := range fields {
		sample := f.Name + ":值"
		insert := f.Name + ":"
		switch f.Type {
		case "int":
			sample = f.Name + "=0"
			insert = f.Name + "="
		case "bool":
			sample = f.Name + "=1"
			insert = f.Name + "="
		case "time":
			sample = f.Name + ">=2026-11-01"
			insert = f.Name + ">="
		}
		desc := f.Label + " · " + typeNames[f.Type]
		if f.Raw {
			desc += " · 原始字段"
		}
		rows = append(rows, [4]string{"字段", sample, desc, insert})
	}

	if tab != 0 {
		return rows
	}
	riskCodes := make([]string, 0, len(ruleText))
	for code := range ruleText {
		riskCodes = append(riskCodes, code)
	}
	sort.Strings(riskCodes)
	for _, code := range riskCodes {
		rows = append(rows, [4]string{"风险", "risk:" + code, strings.TrimSpace(ruleText[code]), "risk:" + code})
	}
	return rows
}

func syntaxRulesForTab(tab int) [][4]string {
	rows := [][4]string{
		{"基础", "关键字", "直接输入关键字，对当前表执行全文搜索", "chrome"},
		{"基础", "field:value", "包含匹配；* 可匹配任意字符", "image:*chrome.exe"},
		{"基础", "field!:value", "不包含匹配", "image!:powershell.exe"},
		{"基础", "field=value", "精确匹配", "pid=1234"},
		{"基础", "field!=value", "排除精确匹配", "pid!=4"},
		{"逻辑", "and / or / not", "条件之间必须显式写 and；and 优先于 or", "AND"},
		{"逻辑", "( ... )", "使用括号组合条件", "()"},
		{"逻辑", "-条件", "排除条件", "-"},
		{"时间", "ts>=2026-11-01", "事件时间不早于指定日期", "ts>=2026-11-01"},
		{"时间", `ts<="2026-11-07 18:00:00"`, "事件时间不晚于指定时间", `ts<="2026-11-07 18:00:00"`},
	}
	switch tab {
	case 1:
		specific := [][4]string{
			{"过滤进程", "image:*chrome.exe", "按进程名或路径包含匹配，* 可匹配任意字符", "image:*chrome.exe"},
			{"过滤进程", `image:"C:\Program Files\Google\Chrome\Application\chrome.exe"`, "路径含空格时使用双引号", `image:"C:\Program Files\Google\Chrome\Application\chrome.exe"`},
			{"过滤PID", "pid=1234", "按进程 PID 精确匹配", "pid=1234"},
			{"过滤GUID", "guid:{01234567-89ab-cdef-0123-456789abcdef}", "按进程 GUID 精确筛选进程实例", "guid:{01234567-89ab-cdef-0123-456789abcdef}"},
			{"命令行", "cmdline:*powershell*", "按完整命令行包含匹配", "cmdline:*powershell*"},
			{"父进程", "parent:*services.exe", "按父进程名称或路径匹配", "parent:*services.exe"},
			{"Hash", "hashes:SHA256", "按文件哈希算法或哈希值匹配", "hashes:SHA256"},
			{"完整性", "integrity=High", "按完整性级别精确匹配", "integrity=High"},
		}
		return append(rows, specific...)
	case 2:
		specific := [][4]string{
			{"过滤域名", "query:example.com", "按查询域名包含匹配", "query:example.com"},
			{"过滤域名", "query:*.github.com", "使用 * 匹配子域名", "query:*.github.com"},
			{"过滤IP", "results:203.0.113.10", "按 DNS 解析结果包含匹配", "results:203.0.113.10"},
			{"状态", "status=0", "0 表示查询成功；status!=0 可查失败记录", "status=0"},
			{"规则", "rule:github-api", "按命中的 Sysmon 规则名匹配", "rule:github-api"},
			{"进程", "image:*chrome.exe", "按发起查询的进程匹配", "image:*chrome.exe"},
			{"PID", "pid=1234", "按发起查询的进程 PID 精确匹配", "pid=1234"},
		}
		return append(rows, specific...)
	default:
		specific := [][4]string{
			{"过滤IP", "dst_ip:203.0.113.10", "按目的 IP 包含匹配", "dst_ip:203.0.113.10"},
			{"过滤IP", "dst_ip=203.0.113.10", "按目的 IP 精确匹配", "dst_ip=203.0.113.10"},
			{"过滤域名", "dst_host:example.com", "按目的域名包含匹配", "dst_host:example.com"},
			{"过滤域名", "dst_host:*.github.com", "使用 * 匹配子域名", "dst_host:*.github.com"},
			{"过滤进程", "image:*chrome.exe", "按进程名或路径包含匹配", "image:*chrome.exe"},
			{"协议", "proto=TCP", "按 TCP、UDP 等协议精确匹配", "proto=TCP"},
			{"数值", "dst_port=443", "端口等数值字段支持 = != > < >= <=", "dst_port=443"},
			{"布尔", "public=1", "布尔字段使用 1/0，也接受 true/false", "public=1"},
			{"风险", "risk:R6", "按风险编码筛选；风险编码之间用空格分隔", "risk:R6"},
		}
		return append(rows, specific...)
	}
}
