//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/wstr"
)

func (a *nativeApp) openStatsPanel() {
	if a.tabs == nil {
		a.openConnStatsPanel(a.table.currentExpr())
		return
	}
	switch a.tabs.active {
	case 1:
		a.openProcessStatsPanel(a.procQueryExpr(a.tabs.procExpr))
	case 2:
		a.openDNSStatsPanel(strings.TrimSpace(a.tabs.dnsExpr))
	default:
		a.openConnStatsPanel(a.table.currentExpr())
	}
}

func (a *nativeApp) openConnStatsPanel(expr string) {
	stats, err := a.cfg.db.IRStats(expr)
	if err != nil {
		a.message("连接统计", "统计失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("连接统计 - 应急排查").
		Size(ui.Dpi(1120, 720)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))
	lblScope := ui.NewStatic(modal, ui.OptsStatic().
		Text("").
		Position(ui.Dpi(12, 10)).
		Size(ui.Dpi(1096, 20)))
	tab := ui.NewTab(modal, ui.OptsTab().
		Titles("应急总览", "TOP 进程", "TOP 目标 IP", "TOP 域名", "风险分布").
		Position(ui.Dpi(12, 36)).
		Size(ui.Dpi(1096, 606)).
		Layout(ui.LAY_RESIZE_RESIZE))

	overview := newStatsList(tab.Item(0).Child(), []tabCol{
		{"指标", 260}, {"值", 180},
	})
	proc := newStatsList(tab.Item(1).Child(), []tabCol{
		{"进程", 500}, {"连接数", 110}, {"外网连接", 110}, {"风险连接", 110},
	})
	ip := newStatsList(tab.Item(2).Child(), []tabCol{
		{"目标 IP", 220}, {"归属地", 240}, {"连接数", 110}, {"涉及进程", 110}, {"风险连接", 110},
	})
	domain := newStatsList(tab.Item(3).Child(), []tabCol{
		{"域名 / 目标主机名", 500}, {"连接数", 110}, {"目的 IP 数", 110}, {"风险连接", 110},
	})
	risk := newStatsList(tab.Item(4).Child(), []tabCol{
		{"规则", 80}, {"说明", 760}, {"命中数", 120},
	})

	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(1008, 664)).
		Width(ui.DpiX(100)))
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	if brush, err := win.GetSysColorBrush(co.COLOR_BTNFACE); err == nil {
		modal.On().WmCtlColorStatic(func(p ui.WmCtlColor) win.HBRUSH {
			_, _ = p.Hdc().SetBkMode(co.BKMODE_TRANSPARENT)
			if p.HwndControl() == lblScope.Hwnd() {
				_, _ = p.Hdc().SetTextColor(win.COLORREF(0x000000FF))
			}
			return brush
		})
	}

	proc.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopProc) {
			a.pivotStatsFilter(modal, 0, "image="+quoteExprValue(stats.TopProc[int(p.IItem)].Key))
		}
	})
	ip.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopIP) {
			a.pivotStatsFilter(modal, 0, "dst_ip="+quoteExprValue(stats.TopIP[int(p.IItem)].Key))
		}
	})
	domain.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopDomain) {
			a.pivotStatsFilter(modal, 0, "dst_host="+quoteExprValue(stats.TopDomain[int(p.IItem)].Key))
		}
	})
	risk.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.Risks) {
			a.pivotStatsFilter(modal, 0, "risk:"+stats.Risks[int(p.IItem)].Key)
		}
	})

	modal.On().WmCreate(func(_ ui.WmCreate) int {
		tab.Item(0).Select()
		overview.AddItem("连接总数", commaInt(stats.Conns))
		overview.AddItem("外网连接", commaInt(stats.Public))
		overview.AddItem("出站连接", commaInt(stats.Outbound))
		overview.AddItem("进程名数", commaInt(stats.Processes))
		overview.AddItem("目的 IP 数", commaInt(stats.DstIPs))
		overview.AddItem("域名数", commaInt(stats.Domains))
		for _, r := range stats.TopProc {
			proc.AddItem(r.Key, commaInt(r.N), commaInt(r.Public), commaInt(r.Risky))
		}
		for _, r := range stats.TopIP {
			ip.AddItem(r.Key, r.Sub, commaInt(r.N), commaInt(r.Targets), commaInt(r.Risky))
		}
		for _, r := range stats.TopDomain {
			domain.AddItem(r.Key, commaInt(r.N), commaInt(r.Targets), commaInt(r.Risky))
		}
		for _, r := range stats.Risks {
			risk.AddItem(r.Key, ruleText[r.Key], commaInt(r.N))
		}
		if expr == "" {
			_ = lblScope.Hwnd().SetWindowText("统计基于当前连接筛选条件（当前未设置筛选，统计全部连接） · 双击统计行可回到连接筛选")
		} else {
			_ = lblScope.Hwnd().SetWindowText(fmt.Sprintf("统计基于当前连接筛选条件 · 当前筛选：%s · 双击统计行可回到连接筛选", expr))
		}
		return 0
	})
	modal.ShowModal()
}

func (a *nativeApp) openProcessStatsPanel(expr string) {
	stats, err := a.cfg.db.ProcessStats(expr)
	if err != nil {
		a.message("进程统计", "统计失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("进程统计 - 应急排查").
		Size(ui.Dpi(1120, 720)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))
	lblScope := ui.NewStatic(modal, ui.OptsStatic().
		Text("").
		Position(ui.Dpi(12, 10)).
		Size(ui.Dpi(1096, 20)))
	tab := ui.NewTab(modal, ui.OptsTab().
		Titles("统计总览", "TOP 进程", "TOP 父进程", "TOP 用户", "风险进程").
		Position(ui.Dpi(12, 36)).
		Size(ui.Dpi(1096, 606)).
		Layout(ui.LAY_RESIZE_RESIZE))

	overview := newStatsList(tab.Item(0).Child(), []tabCol{
		{"指标", 300}, {"值", 180},
	})
	topProcess := newStatsList(tab.Item(1).Child(), []tabCol{
		{"进程", 760}, {"进程实例", 130},
	})
	topParent := newStatsList(tab.Item(2).Child(), []tabCol{
		{"父进程", 760}, {"子进程实例", 130},
	})
	topUser := newStatsList(tab.Item(3).Child(), []tabCol{
		{"用户", 760}, {"进程实例", 130},
	})
	riskProcess := newStatsList(tab.Item(4).Child(), []tabCol{
		{"进程", 760}, {"风险连接", 130},
	})
	addStatsCloseButton(modal)
	styleStatsScope(modal, lblScope)

	topProcess.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopProcess) {
			a.pivotStatsFilter(modal, 1, "image="+quoteExprValue(stats.TopProcess[int(p.IItem)].Key))
		}
	})
	topParent.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopParent) {
			a.pivotStatsFilter(modal, 1, "parent="+quoteExprValue(stats.TopParent[int(p.IItem)].Key))
		}
	})
	topUser.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopUser) {
			a.pivotStatsFilter(modal, 1, "user="+quoteExprValue(stats.TopUser[int(p.IItem)].Key))
		}
	})
	riskProcess.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopProcessWithRisk) {
			a.pivotStatsFilter(modal, 1, "image="+quoteExprValue(stats.TopProcessWithRisk[int(p.IItem)].Key))
		}
	})

	modal.On().WmCreate(func(_ ui.WmCreate) int {
		tab.Item(0).Select()
		overview.AddItem("进程实例数", commaInt(stats.Total))
		overview.AddItem("有网络连接", commaInt(stats.WithNetwork))
		overview.AddItem("无网络连接", commaInt(stats.WithoutNetwork))
		overview.AddItem("有结束事件", commaInt(stats.Ended))
		overview.AddItem("连接总数", commaInt(stats.Connections))
		overview.AddItem("外网连接", commaInt(stats.PublicConnections))
		overview.AddItem("风险连接", commaInt(stats.RiskyConnections))
		overview.AddItem("涉及用户数", commaInt(stats.Users))
		for _, r := range stats.TopProcess {
			topProcess.AddItem(r.Key, commaInt(r.N))
		}
		for _, r := range stats.TopParent {
			topParent.AddItem(r.Key, commaInt(r.N))
		}
		for _, r := range stats.TopUser {
			topUser.AddItem(r.Key, commaInt(r.N))
		}
		for _, r := range stats.TopProcessWithRisk {
			riskProcess.AddItem(r.Key, commaInt(r.N))
		}
		_ = lblScope.Hwnd().SetWindowText(statsScopeText("进程", expr, "双击统计行可回到进程筛选"))
		return 0
	})
	modal.ShowModal()
}

func (a *nativeApp) openDNSStatsPanel(expr string) {
	stats, err := a.cfg.db.DNSStats(expr)
	if err != nil {
		a.message("DNS统计", "统计失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("DNS统计 - 应急排查").
		Size(ui.Dpi(1120, 720)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))
	lblScope := ui.NewStatic(modal, ui.OptsStatic().
		Text("").
		Position(ui.Dpi(12, 10)).
		Size(ui.Dpi(1096, 20)))
	tab := ui.NewTab(modal, ui.OptsTab().
		Titles("统计总览", "TOP 域名", "TOP 进程", "TOP 解析 IP", "风险分布").
		Position(ui.Dpi(12, 36)).
		Size(ui.Dpi(1096, 606)).
		Layout(ui.LAY_RESIZE_RESIZE))

	overview := newStatsList(tab.Item(0).Child(), []tabCol{
		{"指标", 300}, {"值", 180},
	})
	topDomain := newStatsList(tab.Item(1).Child(), []tabCol{
		{"查询域名", 560}, {"查询数", 100}, {"解析结果数", 110}, {"失败数", 90},
	})
	topProcess := newStatsList(tab.Item(2).Child(), []tabCol{
		{"进程", 560}, {"查询数", 100}, {"域名数", 100}, {"失败数", 90},
	})
	topResult := newStatsList(tab.Item(3).Child(), []tabCol{
		{"解析 IP", 500}, {"归属地", 250}, {"关联查询数", 110},
	})
	risk := newStatsList(tab.Item(4).Child(), []tabCol{
		{"规则", 80}, {"说明", 760}, {"命中数", 120},
	})
	addStatsCloseButton(modal)
	styleStatsScope(modal, lblScope)

	topDomain.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopDomain) {
			a.pivotStatsFilter(modal, 2, "query="+quoteExprValue(stats.TopDomain[int(p.IItem)].Key))
		}
	})
	topProcess.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopProcess) {
			a.pivotStatsFilter(modal, 2, "image="+quoteExprValue(stats.TopProcess[int(p.IItem)].Key))
		}
	})
	topResult.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.TopResult) {
			a.pivotStatsFilter(modal, 2, "results="+quoteExprValue(stats.TopResult[int(p.IItem)].Key))
		}
	})
	risk.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 && int(p.IItem) < len(stats.Risks) && stats.Risks[int(p.IItem)].N > 0 {
			a.pivotStatsFilter(modal, 2, "risk:"+stats.Risks[int(p.IItem)].Key)
		}
	})

	modal.On().WmCreate(func(_ ui.WmCreate) int {
		tab.Item(0).Select()
		overview.AddItem("DNS 记录数", commaInt(stats.Total))
		overview.AddItem("查询域名数", commaInt(stats.Domains))
		overview.AddItem("解析 IP 数", commaInt(stats.Results))
		overview.AddItem("涉及进程数", commaInt(stats.Processes))
		overview.AddItem("失败查询数", commaInt(stats.Failed))
		overview.AddItem("境外解析数", commaInt(stats.Foreign))
		overview.AddItem("来源数", commaInt(stats.Sources))
		for _, r := range stats.TopDomain {
			topDomain.AddItem(r.Key, commaInt(r.N), commaInt(r.Targets), commaInt(r.Risky))
		}
		for _, r := range stats.TopProcess {
			topProcess.AddItem(r.Key, commaInt(r.N), commaInt(r.Targets), commaInt(r.Risky))
		}
		for _, r := range stats.TopResult {
			topResult.AddItem(r.Key, r.Sub, commaInt(r.N))
		}
		for _, r := range stats.Risks {
			risk.AddItem(r.Key, dnsRuleText[r.Key], commaInt(r.N))
		}
		_ = lblScope.Hwnd().SetWindowText(statsScopeText("DNS", expr, "双击统计行可回到 DNS 筛选"))
		return 0
	})
	modal.ShowModal()
}

func statsScopeText(kind, expr, action string) string {
	if strings.TrimSpace(expr) == "" {
		return fmt.Sprintf("统计基于当前%s筛选条件（当前未设置筛选，统计全部数据） · %s", kind, action)
	}
	return fmt.Sprintf("统计基于当前%s筛选条件 · 当前筛选：%s · %s", kind, expr, action)
}

func addStatsCloseButton(modal *ui.Modal) {
	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(1008, 664)).
		Width(ui.DpiX(100)))
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
}

func styleStatsScope(modal *ui.Modal, lblScope *ui.Static) {
	if brush, err := win.GetSysColorBrush(co.COLOR_BTNFACE); err == nil {
		modal.On().WmCtlColorStatic(func(p ui.WmCtlColor) win.HBRUSH {
			_, _ = p.Hdc().SetBkMode(co.BKMODE_TRANSPARENT)
			if p.HwndControl() == lblScope.Hwnd() {
				_, _ = p.Hdc().SetTextColor(win.COLORREF(0x000000FF))
			}
			return brush
		})
	}
}

func newStatsList(parent ui.Parent, cols []tabCol) *ui.ListView {
	opts := ui.OptsListView().
		Position(ui.Dpi(0, 0)).
		Size(ui.Dpi(1090, 620)).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.LVS_REPORT | co.LVS_SHOWSELALWAYS | co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT | co.LVS_EX_DOUBLEBUFFER | co.LVS_EX_INFOTIP)
	for _, c := range cols {
		opts.Column(c.title, ui.DpiX(c.width))
	}
	lv := ui.NewListView(parent, opts)
	lv.On().LvnGetInfoTip(func(p *win.NMLVGETINFOTIP) {
		if p.IItem >= 0 && p.ISubItem >= 0 && int(p.ISubItem) < lv.ColCount() {
			wstr.EncodeToBuf(p.PszText(), lv.Item(int(p.IItem)).Text(int(p.ISubItem)))
		}
	})
	return lv
}

func (a *nativeApp) pivotStatsFilter(modal *ui.Modal, tab int, expr string) {
	modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	if tab < 0 || tab > 2 {
		tab = 0
	}
	a.tabs.selectTab(tab)
	a.txtSyntax.SetText(expr)
	a.applySyntax()
}
