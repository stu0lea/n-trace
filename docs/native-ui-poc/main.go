//go:build windows

package main

import (
	"fmt"
	"runtime"
	"strconv"
	"sync"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/wstr"
)

// 模拟后端：500k 行数据，按块加载（真实实现里是 SQLite 分页查询）。
const totalRows = 500000
const blockSize = 512

type rowData [12]string

var (
	src []rowData // 假数据源
)

// 块缓存：块号 -> 行切片
type blockCache struct {
	mu     sync.Mutex
	blocks map[int][]rowData
	order  []int
	max    int
}

func (c *blockCache) get(block int) ([]rowData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.blocks[block]
	return b, ok
}

func (c *blockCache) put(block int, b []rowData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.blocks[block]; ok {
		return
	}
	c.blocks[block] = b
	c.order = append(c.order, block)
	if len(c.order) > c.max {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.blocks, old)
	}
}

func main() {
	runtime.LockOSThread()

	src = make([]rowData, totalRows)
	for i := range src {
		src[i] = rowData{
			"2026-11-07 14:0" + strconv.Itoa(i%10) + ":00",
			strconv.Itoa(1000 + i%4000),
			"svchost.exe",
			"10.1." + strconv.Itoa(i/65025%255) + "." + strconv.Itoa(i%255),
			strconv.Itoa(40000 + i%20000),
			"TCP",
			"104.18." + strconv.Itoa(i%255) + ".11",
			"443",
			"out",
			"公开",
			"",
			"",
		}
	}

	wnd := ui.NewMain(ui.OptsMain().
		Title("Trace-Audit — 网络连接审计").
		Size(ui.Dpi(1400, 800)))

	// ---- 工具条 ----
	y1 := ui.DpiY(12)
	ui.NewStatic(wnd, ui.OptsStatic().Text("数据源：C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx").
		Position(ui.Dpi(10, y1)))

	y2 := ui.DpiY(48)
	cbLogic := ui.NewComboBox(wnd, ui.OptsComboBox().
		Position(ui.Dpi(10, y2)).Width(ui.DpiX(70)).
		Texts("AND", "OR").Select(0))
	cbField := ui.NewComboBox(wnd, ui.OptsComboBox().
		Position(ui.Dpi(88, y2)).Width(ui.DpiX(140)).
		Texts("进程", "目标 IP", "目标端口", "协议", "用户", "域名").Select(0))
	txtVal := ui.NewEdit(wnd, ui.OptsEdit().
		Position(ui.Dpi(236, y2)).Width(ui.DpiX(200)))
	btnAdd := ui.NewButton(wnd, ui.OptsButton().
		Text("添加条件").Position(ui.Dpi(446, y2)).Width(ui.DpiX(80)))
	btnReset := ui.NewButton(wnd, ui.OptsButton().
		Text("重置").Position(ui.Dpi(534, y2)).Width(ui.DpiX(60)))
	btnImp := ui.NewButton(wnd, ui.OptsButton().
		Text("导入日志").Position(ui.Dpi(610, y2)).Width(ui.DpiX(90)))
	btnExp := ui.NewButton(wnd, ui.OptsButton().
		Text("导出日志").Position(ui.Dpi(708, y2)).Width(ui.DpiX(90)))

	// ---- 虚拟表格 ----
	lv := ui.NewListView(wnd, ui.OptsListView().
		Position(ui.Dpi(10, 84)).
		Size(ui.Dpi(1380, 660)).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.LVS_REPORT|co.LVS_OWNERDATA|co.LVS_SHOWSELALWAYS).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("时间", ui.DpiX(150)).
		Column("PID", ui.DpiX(60)).
		Column("进程", ui.DpiX(140)).
		Column("源 IP", ui.DpiX(130)).
		Column("源端口", ui.DpiX(70)).
		Column("协议", ui.DpiX(60)).
		Column("目标 IP", ui.DpiX(130)).
		Column("目标端口", ui.DpiX(75)).
		Column("方向", ui.DpiX(50)).
		Column("Geo", ui.DpiX(60)).
		Column("风险", ui.DpiX(90)).
		Column("详情", ui.DpiX(60)))

	sbar := ui.NewStatusBar(wnd, ui.OptsStatusBar().
		FixedPart(ui.DpiX(120), "总计 0 行").
		FlexPart(1, "就绪").
		FixedPart(ui.DpiX(120), "耗时 0 ms"))

	cache := &blockCache{blocks: map[int][]rowData{}, max: 16}

	lv.On().LvnGetDispInfo(func(p *win.NMLVDISPINFO) {
		if p.Item.Mask&co.LVIF_TEXT == 0 {
			return
		}
		i, sub := int(p.Item.IItem), int(p.Item.ISubItem)
		if i < 0 || i >= totalRows || sub < 0 || sub >= 12 {
			return
		}
		if b, ok := cache.get(i / blockSize); ok {
			wstr.EncodeToBuf(p.Item.PszText(), b[i%blockSize][sub])
			return
		}
		wstr.EncodeToBuf(p.Item.PszText(), "…")
		go func(block int) {
			b := src[block*blockSize : (block+1)*blockSize]
			cache.put(block, b)
			wnd.Hwnd().PostMessage(co.WM_APP+1, win.WPARAM(0), 0)
		}(i / blockSize)
	})

	wnd.On().Wm(co.WM_APP+1, func(p ui.Wm) uintptr {
		lv.Hwnd().SendMessage(co.WM(co.LVM_REDRAWITEMS), win.WPARAM(0), win.LPARAM(totalRows-1))
		return 0
	})

	// ---- 检索（模拟：worker 线程算完回主线程） ----
	btnAdd.On().BnClicked(func() {
		sbar.Part(1).SetText(fmt.Sprintf("筛选 %s %s = %q",
			cbLogic.CurrentText(), cbField.CurrentText(), txtVal.Text()))
	})

	btnReset.On().BnClicked(func() {
		txtVal.SetText("")
		cbLogic.SelectIndex(0)
		cbField.SelectIndex(0)
		sbar.Part(1).SetText("已重置")
	})

	btnImp.On().BnClicked(func() {
		sbar.Part(1).SetText("导入：打开系统文件选择框（IFileOpenDialog）")
	})
	btnExp.On().BnClicked(func() {
		sbar.Part(1).SetText("导出：流式写 CSV")
	})

	wnd.On().WmCreate(func(_ ui.WmCreate) int {
		lv.Hwnd().SendMessage(co.WM(co.LVM_SETITEMCOUNT), win.WPARAM(totalRows), 0)
		sbar.Part(0).SetText(fmt.Sprintf("总计 %d 行", totalRows))
		return 0
	})

	wnd.RunAsMain()
}
