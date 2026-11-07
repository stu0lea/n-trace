//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/wstr"
)

func showDetailWindow(parent ui.Parent, c *Conn, loc *time.Location) {
	defer func() {
		if r := recover(); r != nil {
			appPrintf("详情窗口异常: %v\n%s", r, debug.Stack())
		}
	}()
	if c == nil {
		return
	}
	modal := ui.NewModal(parent, ui.OptsModal().
		Title("连接详情 - "+displayBase(c.Image)).
		Size(ui.Dpi(920, 680)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	lv := ui.NewListView(modal, ui.OptsListView().
		Position(ui.Dpi(12, 12)).
		Size(ui.Dpi(880, 396)).
		CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS|co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("字段", ui.DpiX(170)).
		Column("值", ui.DpiX(680)))

	lblRaw := ui.NewStatic(modal, ui.OptsStatic().
		Text(fmt.Sprintf("原始 JSON（%d 个字段）", len(c.Raw))).
		Position(ui.Dpi(12, 420)).
		Size(ui.Dpi(880, 20)))

	edRaw := ui.NewEdit(modal, ui.OptsEdit().
		Position(ui.Dpi(12, 444)).
		Width(ui.DpiX(880)).
		Height(ui.DpiY(154)).
		CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL|co.ES_AUTOHSCROLL).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL|co.WS_HSCROLL))

	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(802, 610)).
		Width(ui.DpiX(90)))

	lv.On().LvnGetInfoTip(func(p *win.NMLVGETINFOTIP) {
		if p.IItem < 0 || p.ISubItem != 1 {
			return
		}
		item := lv.Item(int(p.IItem))
		if txt := item.Text(1); txt != "" {
			wstr.EncodeToBuf(p.PszText(), txt)
		}
	})
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	modal.On().WmCreate(func(_ ui.WmCreate) int {
		fillDetailList(lv, c, loc)
		edRaw.SetText(detailJSON(c.Raw))
		_ = lblRaw
		return 0
	})

	modal.ShowModal()
}

func fillDetailList(lv *ui.ListView, c *Conn, loc *time.Location) {
	dir := "入站"
	if c.Out {
		dir = "出站"
	}
	risk := "无"
	if len(c.Risk) > 0 {
		parts := make([]string, 0, len(c.Risk))
		for _, r := range c.Risk {
			if txt := ruleText[r]; txt != "" {
				parts = append(parts, r+" "+txt)
			} else {
				parts = append(parts, r)
			}
		}
		risk = strings.Join(parts, "；")
	}
	rows := [][2]string{
		{"时间", time.UnixMilli(c.TS).In(loc).Format("2006-01-02 15:04:05.000")},
		{"主机", c.Host},
		{"进程", c.Image},
		{"PID", c.PID},
		{"用户", c.User},
		{"进程 GUID", c.Guid},
		{"命令行", c.CmdLine},
		{"父进程", c.Parent},
		{"协议", c.Proto},
		{"方向", dir},
		{"五元组", fmt.Sprintf("%s:%s -> %s:%s", c.SrcIP, c.SrcPort, c.DstIP, c.DstPort)},
		{"域名", c.DstHost},
		{"端口名", c.PortNm},
		{"归属地", c.Geo},
		{"内外网", boolText(c.Public, "外网", "内网")},
		{"IPv6", boolText(c.V6, "是", "否")},
		{"完整性", c.Integ},
		{"来源", c.Source},
		{"风险", risk},
	}
	for _, row := range rows {
		lv.AddItem(row[0], row[1])
	}
}

func detailJSON(raw map[string]string) string {
	if len(raw) == 0 {
		return "无"
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(raw))
	for _, k := range keys {
		ordered[k] = raw[k]
	}
	b, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return "无法序列化原始字段：" + err.Error()
	}
	return toCRLF(string(b))
}

func boolText(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}
