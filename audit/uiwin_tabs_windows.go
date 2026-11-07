//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

type nativeTabs struct {
	app       *nativeApp
	tab       *ui.Tab
	conn      *connTable
	proc      *ui.ListView
	dns       *ui.ListView
	procTable *sharedVirtualTable[procRow]
	dnsTable  *sharedVirtualTable[*DNSQ]

	procExpr string
	dnsExpr  string

	active   int
	procSort string
	procDesc bool
	dnsSort  string
	dnsDesc  bool
}

func newNativeTabs(a *nativeApp) *nativeTabs {
	tab := ui.NewTab(a.wnd, ui.OptsTab().
		Titles("连接", "进程", "DNS").
		Position(ui.Dpi(12, 124)).
		Size(ui.Dpi(600, 300)).
		Layout(ui.LAY_RESIZE_RESIZE))

	t := &nativeTabs{
		app: a, tab: tab,
		procSort: "start", procDesc: true,
		dnsSort: "ts", dnsDesc: true,
	}
	t.conn = newConnTable(a, tab.Item(0).Child())
	t.proc = newTabList(tab.Item(1).Child(),
		[]tabCol{
			{"序号", 48}, {"进程", 155}, {"PID", 58}, {"用户", 85},
			{"进程GUID", 110}, {"命令行", 180}, {"父进程", 130}, {"哈希", 110},
			{"连接数", 70}, {"公网", 58}, {"目的IP数", 75}, {"启动", 150},
			{"结束", 150}, {"风险", 55}, {"来源", 85},
		})
	t.dns = newTabList(tab.Item(2).Child(),
		[]tabCol{
			{"序号", 48}, {"时间", 150}, {"主机", 85}, {"PID", 58}, {"进程", 155},
			{"用户", 85}, {"进程GUID", 110}, {"查询域名", 170}, {"解析结果", 230},
			{"归属地", 180}, {"状态", 65}, {"规则", 70}, {"风险", 65},
		})
	t.procTable = newSharedVirtualTable(
		a, t.proc, "进程",
		snapshotNow,
		a.cfg.db.CountProcessesFilteredAsOf,
		a.cfg.db.PageProcsAsOf,
		a.processTableCell,
		nil,
	)
	t.dnsTable = newSharedVirtualTable(
		a, t.dns, "DNS",
		snapshotNow,
		a.cfg.db.CountDNSFilteredAsOf,
		a.cfg.db.PageDNSAsOf,
		a.dnsTableCell,
		nil,
	)
	t.bind()
	t.setProcSortArrow(11, true)
	t.setDNSSortArrow(1, true)
	return t
}

func snapshotNow(string) (int64, error) {
	return time.Now().UnixMilli(), nil
}

func (t *nativeTabs) fitTimeColumns() {
	const sample = "8888-88-88 88:88:88"
	minWidth := ui.DpiX(150)
	fitListViewColumn(t.proc, 11, sample, minWidth)
	fitListViewColumn(t.proc, 12, sample, minWidth)
	fitListViewColumn(t.dns, 1, sample, minWidth)
}

func processTimeText(ms int64, loc *time.Location) string {
	if ms <= 0 {
		return "-"
	}
	return timeText(ms, loc)
}

type tabCol struct {
	title string
	width int
}

var processSortColumns = []string{
	"", "image", "pid", "user", "guid", "cmdline", "parent", "hashes",
	"n", "pub", "ips", "start", "end", "risky", "source",
}

var dnsSortColumns = []string{
	"", "ts", "host", "pid", "image", "user", "guid", "query", "results", "geo",
	"status", "rule_name", "risk",
}

func (a *nativeApp) processTableCell(p procRow, col, row int) string {
	switch col {
	case 0:
		return strconv.Itoa(row + 1)
	case 1:
		return p.Image
	case 2:
		return p.PID
	case 3:
		return p.User
	case 4:
		return p.Guid
	case 5:
		return p.CmdLine
	case 6:
		return p.Parent
	case 7:
		return p.Hashes
	case 8:
		return strconv.Itoa(p.N)
	case 9:
		return strconv.Itoa(p.Pub)
	case 10:
		return strconv.Itoa(p.IPs)
	case 11:
		return processTimeText(p.Start, a.loc)
	case 12:
		return processTimeText(p.End, a.loc)
	case 13:
		return strconv.Itoa(p.Risky)
	case 14:
		return p.Source
	}
	return ""
}

func (a *nativeApp) dnsTableCell(x *DNSQ, col, row int) string {
	if x == nil {
		return ""
	}
	switch col {
	case 0:
		return strconv.Itoa(row + 1)
	case 1:
		return timeText(x.TS, a.loc)
	case 2:
		return x.Host
	case 3:
		return x.PID
	case 4:
		return x.Image
	case 5:
		return x.User
	case 6:
		return x.Guid
	case 7:
		return x.Query
	case 8:
		return x.Results
	case 9:
		return x.Geo
	case 10:
		return x.Status
	case 11:
		return x.Rule
	case 12:
		return strings.Join(x.Risk, " ")
	}
	return ""
}

func newTabList(parent ui.Parent, cols []tabCol) *ui.ListView {
	opts := ui.OptsListView().
		Position(ui.Dpi(0, 0)).
		Size(ui.Dpi(600, 300)).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.LVS_REPORT | co.LVS_OWNERDATA | co.LVS_SHOWSELALWAYS | co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT | co.LVS_EX_DOUBLEBUFFER | co.LVS_EX_INFOTIP)
	for _, c := range cols {
		opts.Column(c.title, ui.DpiX(c.width))
	}
	return ui.NewListView(parent, opts)
}

func (t *nativeTabs) bind() {
	t.tab.On().TcnSelChange(func() {
		if item, ok := t.tab.ItemSelected(); ok {
			t.active = item.Index()
		}
		t.app.syncSyntaxForTab(t.active)
		t.resizeContent()
		t.refreshActive()
		t.app.refreshFixedCount()
	})
	t.proc.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		row, ok := t.procTable.row(int(p.IItem))
		if !ok {
			return
		}
		showProcessDetailWindow(t.app, row)
	})
	t.proc.On().NmRClick(func(_ *win.NMITEMACTIVATE) {
		t.openProcFilterMenu()
	})
	t.proc.On().LvnColumnClick(func(p *win.NMLISTVIEW) {
		t.sortProcessColumn(int(p.IItem))
	})
	t.dns.On().NmRClick(func(_ *win.NMITEMACTIVATE) {
		t.openDNSFilterMenu()
	})
	t.dns.On().LvnColumnClick(func(p *win.NMLISTVIEW) {
		t.sortDNSColumn(int(p.IItem))
	})
}

func (t *nativeTabs) openDNSFilterMenu() {
	pt, err := win.GetCursorPos()
	if err != nil {
		return
	}
	screenPt := pt
	t.dns.Hwnd().ScreenToClientPt(&pt)
	hit := win.LVHITTESTINFO{Pt: pt}
	ret, _ := t.dns.Hwnd().SendMessage(co.LVM_SUBITEMHITTEST, 0,
		win.LPARAM(unsafe.Pointer(&hit)))
	if ret < 0 || hit.IItem < 0 {
		return
	}
	fields := map[int]string{
		1: "ts", 2: "host", 3: "pid", 4: "image", 5: "user",
		6: "guid", 7: "query", 8: "results", 9: "geo", 10: "status",
		11: "rule_name", 12: "risk",
	}
	field := fields[int(hit.ISubItem)]
	if field == "" {
		return
	}
	value := strings.TrimSpace(t.dns.Item(int(hit.IItem)).Text(int(hit.ISubItem)))
	if value == "" {
		return
	}
	menu, err := win.CreatePopupMenu()
	if err != nil {
		return
	}
	defer menu.DestroyMenu()
	appendMenuItem(menu, 0, 1, "添加为 AND 筛选", 0)
	appendMenuItem(menu, 1, 2, "添加为 OR 筛选", 0)
	t.app.wnd.Hwnd().SetForegroundWindow()
	id, _ := menu.TrackPopupMenu(co.TPM_LEFTALIGN|co.TPM_TOPALIGN|co.TPM_RETURNCMD,
		int(screenPt.X), int(screenPt.Y), t.app.wnd.Hwnd())
	if id != 1 && id != 2 {
		return
	}
	expr, err := dnsColumnFilterExpr(field, value)
	if err != nil {
		t.app.setStatus(err.Error())
		return
	}
	logic := "AND"
	if id == 2 {
		logic = "OR"
	}
	t.app.appendFilterExpr(expr, logic)
}

func dnsColumnFilterExpr(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("当前单元格为空")
	}
	switch field {
	case "ts":
		now := time.Now().In(time.Local).Format("2006-01-02 15:04:05")
		return fmt.Sprintf(`(ts>="%s" and ts<"%s")`, value, now), nil
	case "status":
		return "status=" + quoteExprValue(value), nil
	case "guid":
		return "guid=" + quoteExprValue(value), nil
	default:
		return field + ":" + quoteExprValue(value), nil
	}
}

func (t *nativeTabs) openProcFilterMenu() {
	pt, err := win.GetCursorPos()
	if err != nil {
		return
	}
	screenPt := pt
	t.proc.Hwnd().ScreenToClientPt(&pt)
	hit := win.LVHITTESTINFO{Pt: pt}
	ret, _ := t.proc.Hwnd().SendMessage(co.LVM_SUBITEMHITTEST, 0,
		win.LPARAM(unsafe.Pointer(&hit)))
	if ret < 0 || hit.IItem < 0 {
		return
	}
	fields := map[int]string{
		1: "image", 2: "pid", 3: "user", 4: "guid", 5: "cmdline",
		6: "parent", 7: "hashes", 14: "source",
	}
	field := fields[int(hit.ISubItem)]
	if field == "" {
		return
	}
	value := strings.TrimSpace(t.proc.Item(int(hit.IItem)).Text(int(hit.ISubItem)))
	if value == "" {
		return
	}
	menu, err := win.CreatePopupMenu()
	if err != nil {
		return
	}
	defer menu.DestroyMenu()
	appendMenuItem(menu, 0, 1, "添加为 AND 筛选", 0)
	appendMenuItem(menu, 1, 2, "添加为 OR 筛选", 0)
	t.app.wnd.Hwnd().SetForegroundWindow()
	id, _ := menu.TrackPopupMenu(co.TPM_LEFTALIGN|co.TPM_TOPALIGN|co.TPM_RETURNCMD,
		int(screenPt.X), int(screenPt.Y), t.app.wnd.Hwnd())
	if id == 1 {
		t.app.addCellFilter(field, value, "AND")
	} else if id == 2 {
		t.app.addCellFilter(field, value, "OR")
	}
}

func (t *nativeTabs) listAt(idx int) *ui.ListView {
	switch idx {
	case 1:
		return t.proc
	case 2:
		return t.dns
	default:
		return t.conn.lv
	}
}

func (t *nativeTabs) resizeContent() {
	idx := t.active
	if item, ok := t.tab.ItemSelected(); ok {
		idx = item.Index()
	}
	child := t.tab.Item(idx).Child().Hwnd()
	if child == 0 {
		return
	}
	if rcTab, err := t.tab.Hwnd().GetWindowRect(); err == nil {
		if hParent, err := t.tab.Hwnd().GetParent(); err == nil {
			_ = hParent.ScreenToClientRc(&rcTab)
			t.tab.Hwnd().SendMessage(co.TCM_ADJUSTRECT, 0, win.LPARAM(unsafe.Pointer(&rcTab)))
			child.SetWindowPos(win.HWND(0),
				win.POINT{X: rcTab.Left, Y: rcTab.Top},
				win.SIZE{Cx: rcTab.Right - rcTab.Left, Cy: rcTab.Bottom - rcTab.Top},
				co.SWP_NOZORDER|co.SWP_SHOWWINDOW)
		}
	}
	rc, err := child.GetClientRect()
	if err != nil {
		return
	}
	lv := t.listAt(idx)
	if lv == nil || lv.Hwnd() == 0 {
		return
	}
	setBounds(lv.Hwnd(), 0, 0, int(rc.Right-rc.Left), int(rc.Bottom-rc.Top))
}

func (t *nativeTabs) selectTab(idx int) {
	if idx < 0 || idx >= t.tab.ItemCount() {
		return
	}
	t.tab.Item(idx).Select()
	t.active = idx
	t.app.syncSyntaxForTab(idx)
	t.resizeContent()
	t.refreshActive()
	t.app.refreshFixedCount()
}

func (t *nativeTabs) refreshActive() {
	switch t.active {
	case 1:
		t.app.refreshProcesses()
	case 2:
		t.app.refreshDNS()
	}
}

func (t *nativeTabs) refreshAfterFilter() {
	switch t.active {
	case 1:
		t.app.refreshProcesses()
	case 2:
		t.app.refreshDNS()
	}
}

func (t *nativeTabs) setProcSortArrow(col int, desc bool) {
	for i := 0; i < t.proc.ColCount(); i++ {
		t.proc.Col(i).SetSortArrow(co.HDF_NONE)
	}
	if col >= 0 && col < t.proc.ColCount() {
		if desc {
			t.proc.Col(col).SetSortArrow(co.HDF_SORTDOWN)
		} else {
			t.proc.Col(col).SetSortArrow(co.HDF_SORTUP)
		}
	}
}

func (t *nativeTabs) setDNSSortArrow(col int, desc bool) {
	for i := 0; i < t.dns.ColCount(); i++ {
		t.dns.Col(i).SetSortArrow(co.HDF_NONE)
	}
	if col >= 0 && col < t.dns.ColCount() {
		if desc {
			t.dns.Col(col).SetSortArrow(co.HDF_SORTDOWN)
		} else {
			t.dns.Col(col).SetSortArrow(co.HDF_SORTUP)
		}
	}
}

func (t *nativeTabs) sortProcessColumn(col int) {
	if col <= 0 || col >= len(processSortColumns) || processSortColumns[col] == "" {
		return
	}
	field := processSortColumns[col]
	if t.procSort == field {
		t.procDesc = !t.procDesc
	} else {
		t.procSort, t.procDesc = field, false
	}
	t.setProcSortArrow(col, t.procDesc)
	t.procTable.reload(strings.TrimSpace(t.procExpr), t.procSort, t.procDesc)
}

func (t *nativeTabs) sortDNSColumn(col int) {
	if col <= 0 || col >= len(dnsSortColumns) || dnsSortColumns[col] == "" {
		return
	}
	field := dnsSortColumns[col]
	if t.dnsSort == field {
		t.dnsDesc = !t.dnsDesc
	} else {
		t.dnsSort, t.dnsDesc = field, false
	}
	t.setDNSSortArrow(col, t.dnsDesc)
	t.dnsTable.reload(strings.TrimSpace(t.dnsExpr), t.dnsSort, t.dnsDesc)
}

func (t *nativeTabs) scrollTop() {
	lv := t.listAt(t.active)
	if lv == nil || lv.Hwnd() == 0 || lv.ItemCount() == 0 {
		return
	}
	lv.Hwnd().SendMessage(co.LVM_ENSUREVISIBLE, 0, 1)
	state := win.LVITEM{
		State:     co.LVIS_FOCUSED | co.LVIS_SELECTED,
		StateMask: co.LVIS_FOCUSED | co.LVIS_SELECTED,
	}
	lv.Hwnd().SendMessage(co.LVM_SETITEMSTATE, 0, win.LPARAM(unsafe.Pointer(&state)))
	lv.Focus()
}

func (a *nativeApp) refreshProcesses() {
	if a.tabs == nil || a.tabs.procTable == nil {
		return
	}
	a.tabs.procTable.refresh(strings.TrimSpace(a.tabs.procExpr), a.tabs.procSort, a.tabs.procDesc)
}

func (a *nativeApp) refreshDNS() {
	if a.tabs == nil || a.tabs.dnsTable == nil {
		return
	}
	a.tabs.dnsTable.refresh(strings.TrimSpace(a.tabs.dnsExpr), a.tabs.dnsSort, a.tabs.dnsDesc)
}
