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

type tableColumn struct {
	title string
	width int
	field string
}

// 列顺序与网页版一致，五元组拆成独立列。
var tableColumns = []tableColumn{
	{"序号", 48, ""},
	{"时间", 150, "ts"},
	{"主机", 90, "host"},
	{"用户", 85, "user"},
	{"PID", 58, "pid"},
	{"进程GUID", 110, "guid"},
	{"进程", 155, "image"},
	{"父进程", 130, "parent"},
	{"命令行", 180, "cmdline"},
	{"哈希", 110, "hashes"},
	{"协议", 50, "proto"},
	{"源 IP", 95, "src_ip"},
	{"源端口", 58, "src_port"},
	{"目标 IP", 100, "dst_ip"},
	{"目标端口", 64, "dst_port"},
	{"域名", 140, "dst_host"},
	{"方向", 46, "outbound"},
	{"Geo", 85, "geo"},
	{"内外网", 55, "public"},
	{"完整性", 55, "integrity"},
	{"规则", 65, "rule_name"},
	{"风险", 50, "risk"},
	{"来源", 85, "source"},
}

type connTable struct {
	app        *nativeApp
	lv         *ui.ListView
	db         *DB
	table      *sharedVirtualTable[*Conn]
	lastDetail time.Time
}

// connHiddenFields 默认隐藏的列：主机、哈希、规则。Geo 列不隐藏，标题显示为“归属地”。
var connHiddenFields = map[string]bool{
	"host": true, "hashes": true, "rule_name": true,
}

func newConnTable(app *nativeApp, parent ui.Parent) *connTable {
	opts := ui.OptsListView().
		CtrlId(30001).
		Position(ui.Dpi(0, 0)).
		Size(ui.Dpi(600, 300)).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.LVS_REPORT | co.LVS_OWNERDATA | co.LVS_SHOWSELALWAYS | co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT | co.LVS_EX_DOUBLEBUFFER | co.LVS_EX_INFOTIP)
	for _, c := range tableColumns {
		title, w := c.title, ui.DpiX(c.width)
		if c.field == "geo" {
			title = "归属地" // Geo 列用中文标题
		}
		if connHiddenFields[c.field] {
			w = 0 // 默认隐藏
		}
		opts.Column(title, w)
	}
	t := &connTable{app: app, lv: ui.NewListView(parent, opts), db: app.cfg.db}
	t.table = newSharedVirtualTable(
		app, t.lv, "连接",
		app.cfg.db.SnapshotMaxID,
		app.cfg.db.CountBefore,
		app.cfg.db.QueryLiteBefore,
		t.cell,
		t.tip,
	)
	t.bind()
	return t
}

// fitTimeColumn 按当前字体实际测量完整时间文本，避免高 DPI 下被排序箭头挤掉。
func (t *connTable) fitTimeColumn() {
	fitListViewColumn(t.lv, 1, "8888-88-88 88:88:88", ui.DpiX(150))
}

func fitListViewColumn(lv *ui.ListView, col int, sample string, minWidth int) {
	if lv == nil || lv.Hwnd() == 0 || col < 0 || col >= lv.ColCount() {
		return
	}
	width := minWidth
	if hdc, err := lv.Hwnd().GetDC(); err == nil {
		var prev win.HFONT
		if hfont, _ := lv.Hwnd().SendMessage(co.WM_GETFONT, 0, 0); hfont != 0 {
			prev, _ = hdc.SelectObjectFont(win.HFONT(hfont))
		}
		if sz, err := hdc.GetTextExtentPoint32(sample); err == nil {
			if need := int(sz.Cx) + ui.DpiX(26); need > width {
				width = need
			}
		}
		if prev != 0 {
			hdc.SelectObjectFont(prev)
		}
		lv.Hwnd().ReleaseDC(hdc)
	}
	lv.Col(col).SetWidth(width)
}

func listHOrigin(lv *ui.ListView) int {
	if lv == nil || lv.Hwnd() == 0 {
		return 0
	}
	var pt win.POINT
	ret, _ := lv.Hwnd().SendMessage(co.LVM_GETORIGIN, 0, win.LPARAM(unsafe.Pointer(&pt)))
	if ret == 0 {
		return 0
	}
	return int(pt.X)
}

func restoreListHOrigin(lv *ui.ListView, origin int) {
	if lv == nil || lv.Hwnd() == 0 || origin <= 0 {
		return
	}
	current := listHOrigin(lv)
	if delta := origin - current; delta != 0 {
		lv.Hwnd().SendMessage(co.LVM_SCROLL, win.WPARAM(delta), 0)
	}
}

func withListRedraw(lv *ui.ListView, fn func()) {
	if lv == nil || lv.Hwnd() == 0 {
		fn()
		return
	}
	hwnd := lv.Hwnd()
	lv.SetRedraw(false)
	defer func() {
		lv.SetRedraw(true)
		hwnd.InvalidateRect(nil, false)
		hwnd.UpdateWindow()
	}()
	fn()
}

func (t *connTable) bind() {
	t.lv.On().LvnColumnClick(func(p *win.NMLISTVIEW) {
		t.sortByColumn(int(p.IItem))
	})
	t.lv.On().LvnItemActivate(func(p *win.NMITEMACTIVATE) {
		if p.IItem >= 0 {
			t.openDetail(int(p.IItem))
		}
	})
	t.lv.On().NmRClick(func(_ *win.NMITEMACTIVATE) {
		t.openCellFilterMenu()
	})
	t.lv.On().LvnKeyDown(func(p *win.NMLVKEYDOWN) {
		if p.WVKey == co.VK_RETURN {
			if sel := t.lv.SelectedItems(); len(sel) > 0 {
				t.openDetail(sel[0].Index())
			}
		}
	})
	t.lv.On().NmCustomDraw(t.onCustomDraw)
}

func (t *connTable) tip(c *Conn, sub, row int) string {
	if c == nil || sub < 0 || sub >= len(tableColumns) {
		return ""
	}
	tip := t.cell(c, sub, row)
	if sub == 21 {
		var parts []string
		for _, r := range c.Risk {
			if txt := ruleText[r]; txt != "" {
				parts = append(parts, r+" "+txt)
			} else {
				parts = append(parts, r)
			}
		}
		tip = strings.Join(parts, "\n")
	}
	return tip
}

func (t *connTable) onCustomDraw(p *win.NMLVCUSTOMDRAW) co.CDRF {
	switch p.Nmcd.DwDrawStage {
	case co.CDDS_PREPAINT:
		return co.CDRF_NOTIFYITEMDRAW
	case co.CDDS_ITEMPREPAINT:
		if p.Nmcd.UItemState&co.CDIS_SELECTED == 0 {
			if c, ok := t.row(int(p.Nmcd.DwItemSpec)); ok && len(c.Risk) > 0 {
				p.ClrText = win.COLORREF(0x002020B4)
			}
		}
		return co.CDRF_DODEFAULT
	}
	return co.CDRF_DODEFAULT
}

func (t *connTable) cell(c *Conn, col, row int) string {
	switch col {
	case 0:
		return strconv.Itoa(row + 1)
	case 1:
		return timeText(c.TS, t.app.loc)
	case 2:
		return c.Host
	case 3:
		return c.User
	case 4:
		return c.PID
	case 5:
		return c.Guid
	case 6:
		return c.Image
	case 7:
		return c.Parent
	case 8:
		return c.CmdLine
	case 9:
		return c.Hashes
	case 10:
		return strings.ToUpper(c.Proto)
	case 11:
		return c.SrcIP
	case 12:
		return c.SrcPort
	case 13:
		return c.DstIP
	case 14:
		return c.DstPort
	case 15:
		return c.DstHost
	case 16:
		if c.Out {
			return "出站"
		}
		return "入站"
	case 17:
		return c.Geo
	case 18:
		if c.Public {
			return "外网"
		}
		return "内网"
	case 19:
		return c.Integ
	case 20:
		return c.Rule
	case 21:
		return strings.Join(c.Risk, " ")
	case 22:
		return c.Source
	}
	return ""
}

func (t *connTable) reload(expr, sortField string, desc bool) {
	t.table.reload(expr, sortField, desc)
}

func (t *connTable) refreshCount() {
	t.table.refreshCount()
}

func (t *connTable) onLiveChange() {
	t.table.refresh(t.table.currentExpr(), t.table.currentSort(), t.table.currentDesc())
}

func (t *connTable) row(index int) (*Conn, bool) {
	return t.table.row(index)
}

func (t *connTable) openDetail(index int) {
	if time.Since(t.lastDetail) < 300*time.Millisecond {
		return
	}
	t.lastDetail = time.Now()

	c, ok := t.row(index)
	if !ok {
		return
	}
	id := c.ID
	go func() {
		full, err := t.db.ConnByID(id)
		if err != nil {
			t.app.wnd.UiThread(func() { t.app.setStatus("读取详情失败：" + err.Error()) })
			return
		}
		t.app.wnd.UiThread(func() {
			showDetailWindow(t.app.wnd, full, t.app.loc)
		})
	}()
}

func (t *connTable) openCellFilterMenu() {
	pt, err := win.GetCursorPos()
	if err != nil {
		return
	}
	t.lv.Hwnd().ScreenToClientPt(&pt)
	hit := win.LVHITTESTINFO{Pt: pt}
	ret, _ := t.lv.Hwnd().SendMessage(co.LVM_SUBITEMHITTEST, 0,
		win.LPARAM(unsafe.Pointer(&hit)))
	if ret < 0 || hit.IItem < 0 {
		return
	}
	row, sub := int(hit.IItem), int(hit.ISubItem)
	if sub < 0 || sub >= len(tableColumns) || tableColumns[sub].field == "" {
		return
	}
	c, ok := t.row(row)
	if !ok {
		return
	}
	value := strings.TrimSpace(t.cell(c, sub, row))
	if value == "" {
		return
	}
	field := tableColumns[sub].field
	menu, err := win.CreatePopupMenu()
	if err != nil {
		return
	}
	defer menu.DestroyMenu()
	appendMenuItem(menu, 0, 1, "添加为 AND 筛选", 0)
	appendMenuItem(menu, 1, 2, "添加为 OR 筛选", 0)
	pos, _ := win.GetCursorPos()
	t.app.wnd.Hwnd().SetForegroundWindow()
	id, _ := menu.TrackPopupMenu(co.TPM_LEFTALIGN|co.TPM_TOPALIGN|co.TPM_RETURNCMD,
		int(pos.X), int(pos.Y), t.app.wnd.Hwnd())
	if id == 1 {
		t.app.addCellFilter(field, value, "AND")
	} else if id == 2 {
		t.app.addCellFilter(field, value, "OR")
	}
}

func cellFilterExpr(field, value string) (string, error) {
	meta, ok := promotedIdx[field]
	if !ok {
		return "", fmt.Errorf("该列不支持筛选")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("当前单元格为空")
	}
	if field == "risk" {
		if parts := strings.Fields(value); len(parts) > 0 {
			value = parts[0]
		}
	}
	if field == "ts" {
		now := time.Now().In(time.Local).Format("2006-01-02 15:04:05")
		return fmt.Sprintf(`(ts>="%s" and ts<"%s")`, value, now), nil
	}
	op := ":"
	switch meta.Type {
	case "int", "bool":
		op = "="
	case "time":
		op = ">="
	}
	switch field {
	case "host", "pid", "guid", "src_ip", "dst_ip", "proto", "integrity", "rule_name", "source":
		op = "="
	}
	return conditionExpr(filterCond{field: meta, op: op, value: value})
}

func (t *connTable) sortByColumn(col int) {
	if col < 0 || col >= len(tableColumns) || tableColumns[col].field == "" {
		return
	}
	field := tableColumns[col].field
	current := t.table.currentSort()
	desc := t.table.currentDesc()
	if current == field {
		desc = !desc
	} else {
		desc = false
	}
	t.setSortArrow(col, desc)
	t.table.reload(t.currentExpr(), field, desc)
}

func (t *connTable) setSortArrow(col int, desc bool) {
	for i := 0; i < len(tableColumns); i++ {
		t.lv.Col(i).SetSortArrow(co.HDF_NONE)
	}
	if col < 0 || col >= len(tableColumns) {
		return
	}
	if desc {
		t.lv.Col(col).SetSortArrow(co.HDF_SORTDOWN)
	} else {
		t.lv.Col(col).SetSortArrow(co.HDF_SORTUP)
	}
}

func (t *connTable) topIndex() int {
	return t.table.topIndex()
}

func (t *connTable) currentExpr() string {
	return t.table.currentExpr()
}

func (t *connTable) currentSort() string {
	return t.table.currentSort()
}

func (t *connTable) currentDesc() bool {
	return t.table.currentDesc()
}

func (t *connTable) totalCount() int {
	return t.table.totalCount()
}
