//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

func showProcessDetailWindow(a *nativeApp, p procRow) {
	var conns []*Conn
	var queryErr error
	if p.Guid != "" {
		expr := "guid=" + quoteExprValue(p.Guid)
		conns, queryErr = a.cfg.db.QueryLite(expr, 2000, 0, "ts", false)
	}

	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("进程详情 - "+displayBase(p.Image)).
		Size(ui.Dpi(1140, 680)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	info := ui.NewListView(modal, ui.OptsListView().
		Position(ui.Dpi(12, 12)).
		Size(ui.Dpi(1100, 220)).
		CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS|co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("字段", ui.DpiX(140)).
		Column("值", ui.DpiX(940)))

	lblConns := ui.NewStatic(modal, ui.OptsStatic().
		Text("该进程连接时间线（按时间正序）").
		Position(ui.Dpi(12, 242)).
		Size(ui.Dpi(1100, 20)))
	lv := ui.NewListView(modal, ui.OptsListView().
		Position(ui.Dpi(12, 264)).
		Size(ui.Dpi(1100, 310)).
		CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS|co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("时间", ui.DpiX(150)).
		Column("方向", ui.DpiX(55)).
		Column("协议", ui.DpiX(60)).
		Column("源地址", ui.DpiX(150)).
		Column("目的IP", ui.DpiX(150)).
		Column("目的端口", ui.DpiX(75)).
		Column("域名", ui.DpiX(220)).
		Column("归属地", ui.DpiX(130)).
		Column("风险", ui.DpiX(100)))

	btnFilter := ui.NewButton(modal, ui.OptsButton().
		Text("在连接页筛选此进程").
		Position(ui.Dpi(12, 590)).
		Width(ui.DpiX(180)))
	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(1022, 590)).
		Width(ui.DpiX(90)))

	btnFilter.On().BnClicked(func() {
		if p.Guid == "" {
			return
		}
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		a.tabs.selectTab(0)
		a.txtSyntax.SetText("guid=" + quoteExprValue(p.Guid))
		a.applySyntax()
	})
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(k ui.WmKey) {
		if k.VirtualKeyCode() == co.VK_ESCAPE && !k.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	if brush, err := win.GetSysColorBrush(co.COLOR_BTNFACE); err == nil {
		modal.On().WmCtlColorStatic(func(p ui.WmCtlColor) win.HBRUSH {
			_, _ = p.Hdc().SetBkMode(co.BKMODE_TRANSPARENT)
			return brush
		})
	}
	lv.On().LvnItemActivate(func(e *win.NMITEMACTIVATE) {
		if e.IItem >= 0 && int(e.IItem) < len(conns) {
			showDetailWindow(modal, conns[int(e.IItem)], a.loc)
		}
	})
	modal.On().WmCreate(func(_ ui.WmCreate) int {
		if p.Guid == "" {
			btnFilter.Hwnd().EnableWindow(false)
		}
		fillProcessInfo(info, p, a.loc)
		if queryErr != nil {
			_ = lblConns.Hwnd().SetWindowText("读取连接失败：" + queryErr.Error())
			return 0
		}
		for _, c := range conns {
			dir := "入站"
			if c.Out {
				dir = "出站"
			}
			src := c.SrcIP
			if c.SrcPort != "" {
				src += ":" + c.SrcPort
			}
			lv.AddItem(timeText(c.TS, a.loc), dir, strings.ToUpper(c.Proto), src,
				c.DstIP, c.DstPort, c.DstHost, c.Geo, strings.Join(c.Risk, " "))
		}
		_ = lblConns.Hwnd().SetWindowText(fmt.Sprintf("该进程连接时间线（%s 条，按时间正序）", commaInt(len(conns))))
		return 0
	})
	modal.ShowModal()
}

func fillProcessInfo(lv *ui.ListView, p procRow, loc *time.Location) {
	first, last := "-", "-"
	if p.First > 0 {
		first = timeText(p.First, loc)
	}
	if p.Last > 0 {
		last = timeText(p.Last, loc)
	}
	start, end := "-", "-"
	if p.Start > 0 {
		start = timeText(p.Start, loc)
	}
	if p.End > 0 {
		end = timeText(p.End, loc)
	}
	rows := [][2]string{
		{"主机", p.Host},
		{"进程", p.Image},
		{"PID", p.PID},
		{"用户", p.User},
		{"进程GUID", p.Guid},
		{"命令行", p.CmdLine},
		{"父进程", p.Parent},
		{"来源", p.Source},
		{"启动时间", start},
		{"结束时间", end},
		{"连接数", commaInt(p.N)},
		{"外网连接数", commaInt(p.Pub)},
		{"目的IP数", commaInt(p.IPs)},
		{"风险条数", commaInt(p.Risky)},
		{"首次外联", first},
		{"最近外联", last},
	}
	for _, row := range rows {
		lv.AddItem(row[0], row[1])
	}
}
