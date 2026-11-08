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

// initialTabBounds 与 layout() 的表格区算法保持一致：
// 创建 Tab 和列表时直接给撑开后的尺寸，避免启动瞬间先以小尺寸闪现。
func initialTabBounds(winW, winH int) (x, y, w, h int) {
	margin := ui.DpiX(12)
	y = ui.DpiY(156)
	bottomH := ui.DpiY(28) + ui.DpiY(2)
	h = winH - y - bottomH - ui.DpiY(8)
	if h < ui.DpiY(120) {
		h = ui.DpiY(120)
	}
	return margin, y, winW - margin*2, h
}

func newNativeTabs(a *nativeApp, winW, winH int) *nativeTabs {
	tabX, tabY, tabW, tabH := initialTabBounds(winW, winH)
	// 列表初始尺寸取 Tab 显示区（去掉表头和边框的近似值），
	// 精确尺寸随后由 resizeContent 校正。
	lvW, lvH := tabW-ui.DpiX(8), tabH-ui.DpiY(30)
	if lvW < ui.DpiX(200) {
		lvW = ui.DpiX(200)
	}
	if lvH < ui.DpiY(100) {
		lvH = ui.DpiY(100)
	}
	tab := ui.NewTab(a.wnd, ui.OptsTab().
		Titles("连接", "进程", "DNS").
		Position(tabX, tabY).
		Size(tabW, tabH).
		Layout(ui.LAY_RESIZE_RESIZE))

	t := &nativeTabs{
		app: a, tab: tab,
		procSort: "start", procDesc: true,
		dnsSort: "ts", dnsDesc: true,
	}
	t.conn = newConnTable(a, tab.Item(0).Child(), lvW, lvH)
	t.proc = newTabList(tab.Item(1).Child(), lvW, lvH,
		[]tabCol{
			{"序号", 48}, {"进程", 155}, {"父进程", 130}, {"命令行", 180},
			{"PID", 58}, {"进程GUID", 110}, {"哈希", 110}, {"用户", 85},
			{"连接数", 70}, {"外网数", 58}, {"目的IP数", 75}, {"启动", 150},
			{"结束", 150}, {"风险", 55}, {"来源", 85},
		}, 6) // 默认隐藏哈希
	t.dns = newTabList(tab.Item(2).Child(), lvW, lvH,
		[]tabCol{
			{"序号", 48}, {"时间", 150}, {"主机", 85}, {"PID", 58}, {"进程", 155},
			{"用户", 85}, {"进程GUID", 110}, {"查询域名", 170}, {"解析结果", 230},
			{"归属地", 180}, {"状态", 65}, {"规则", 70}, {"风险", 65},
		}, 2, 11) // 默认隐藏主机、规则（归属地不隐藏）
	t.procTable = newSharedVirtualTable(
		a, t.proc, "进程",
		snapshotNow,
		func(expr string, asOf int64) (int, error) {
			return a.cfg.db.CountProcessesFilteredAsOf(a.procQueryExpr(expr), asOf)
		},
		func(expr string, limit, offset int, sortField string, desc bool, asOf int64) ([]procRow, error) {
			return a.cfg.db.PageProcsAsOf(a.procQueryExpr(expr), limit, offset, sortField, desc, asOf)
		},
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
	"", "image", "parent", "cmdline", "pid", "guid", "hashes", "user",
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
		return p.Parent
	case 3:
		return p.CmdLine
	case 4:
		return p.PID
	case 5:
		return p.Guid
	case 6:
		return p.Hashes
	case 7:
		return p.User
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

func newTabList(parent ui.Parent, lvW, lvH int, cols []tabCol, hidden ...int) *ui.ListView {
	hideSet := map[int]bool{}
	for _, i := range hidden {
		hideSet[i] = true
	}
	opts := ui.OptsListView().
		Position(ui.Dpi(0, 0)).
		Size(lvW, lvH).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.LVS_REPORT | co.LVS_OWNERDATA | co.LVS_SHOWSELALWAYS | co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT | co.LVS_EX_DOUBLEBUFFER | co.LVS_EX_INFOTIP)
	for i, c := range cols {
		w := ui.DpiX(c.width)
		if hideSet[i] {
			w = 0 // 默认隐藏，创建时置 0 才生效
		}
		opts.Column(c.title, w)
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
		t.app.syncProcNetCheckbox()
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
	numericFields := map[int]string{
		8: "n", 9: "pub", 10: "ips",
	}
	field, isNumeric := numericFields[int(hit.ISubItem)]
	if !isNumeric {
		field = fields[int(hit.ISubItem)]
	}
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
	if id != 1 && id != 2 {
		return
	}
	logic := "AND"
	if id == 2 {
		logic = "OR"
	}
	if isNumeric {
		num, perr := strconv.Atoi(strings.ReplaceAll(value, ",", ""))
		if perr != nil || num < 0 {
			return
		}
		t.app.appendFilterExpr(fmt.Sprintf("%s>=%d", field, num), logic)
		return
	}
	t.app.addCellFilter(field, value, logic)
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
	sel := t.active
	if item, ok := t.tab.ItemSelected(); ok {
		sel = item.Index()
	}
	var rcDisp win.RECT
	if rcTab, err := t.tab.Hwnd().GetWindowRect(); err == nil {
		if hParent, err := t.tab.Hwnd().GetParent(); err == nil {
			_ = hParent.ScreenToClientRc(&rcTab)
			t.tab.Hwnd().SendMessage(co.TCM_ADJUSTRECT, 0, win.LPARAM(unsafe.Pointer(&rcTab)))
			rcDisp = rcTab
		}
	}
	// 调整全部子容器与列表的尺寸；只显示激活页的子容器，
	// 其余隐藏（否则启动瞬间未布局的小尺寸列表会叠在激活页上）。
	for i := 0; i < t.tab.ItemCount(); i++ {
		child := t.tab.Item(i).Child().Hwnd()
		if child == 0 {
			continue
		}
		child.SetWindowPos(win.HWND(0),
			win.POINT{X: rcDisp.Left, Y: rcDisp.Top},
			win.SIZE{Cx: rcDisp.Right - rcDisp.Left, Cy: rcDisp.Bottom - rcDisp.Top},
			co.SWP_NOZORDER)
		if i == sel {
			child.ShowWindow(co.SW_SHOW)
		} else {
			child.ShowWindow(co.SW_HIDE)
		}
		rc, err := child.GetClientRect()
		if err != nil {
			continue
		}
		lv := t.listAt(i)
		if lv == nil || lv.Hwnd() == 0 {
			continue
		}
		setBounds(lv.Hwnd(), 0, 0, int(rc.Right-rc.Left), int(rc.Bottom-rc.Top))
	}
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
	t.app.syncProcNetCheckbox()
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
	hOrigin := listHOrigin(lv)
	lv.Hwnd().SendMessage(co.LVM_ENSUREVISIBLE, 0, 1)
	restoreListHOrigin(lv, hOrigin)
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
