//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/x/winsh"
)

const (
	wmAppRedraw = co.WM_APP + 1
	timerLive   = 1

	menuDataSources = 40001
	menuAbout       = 40002
	menuStats       = 40003
	menuImport      = 40004
)

var (
	gdi32DLL             = syscall.NewLazyDLL("gdi32.dll")
	procCreateSolidBrush = gdi32DLL.NewProc("CreateSolidBrush")
)

type filterCond struct {
	logic string
	field FieldMeta
	op    string
	value string
}

type nativeApp struct {
	cfg   nativeConfig
	wnd   *ui.Main
	loc   *time.Location
	table *connTable
	tabs  *nativeTabs

	cbLogic      *ui.ComboBox
	cbField      *ui.ComboBox
	cbOp         *ui.ComboBox
	txtValue     *ui.Edit
	cbBool       *ui.ComboBox
	lblHot       *ui.Static
	hotBtns      []*ui.Button
	hotValues    []string
	hotCounts    []int
	btnAdd       *ui.Button
	btnReset     *ui.Button
	btnHelp      *ui.Button
	btnExport    *ui.Button
	chkNetOnly   *ui.CheckBox
	procNetOnly  bool
	btnLive      *ui.Button
	icoPlay      win.HICON
	icoPause     win.HICON
	sbar         *ui.StatusBar
	txtSyntax    *ui.Edit
	btnApply     *ui.Button
	lblRefresh   *ui.Static
	edRefresh    *ui.Edit
	lblSec       *ui.Static
	btnTop       *ui.Button
	refreshEvery time.Duration

	hotGen         int
	hotLast        time.Time
	hotCache       map[string]hotEntry
	fixedCountGen  int
	logTotals      LogTotals
	logTotalsReady bool

	fields    []FieldMeta
	fieldIdx  map[string]int
	filterTab int

	busy      int
	importing bool
	exporting bool

	liveMu        sync.Mutex
	live          *LiveStats
	liveWake      chan struct{}
	liveStop      chan struct{}
	lastLiveTotal int64
	liveWasOn     bool
	liveDots      int
}

var dnsFields = []FieldMeta{
	{Name: "ts", Label: "时间", Type: "time"},
	{Name: "host", Label: "主机", Type: "text"},
	{Name: "pid", Label: "PID", Type: "text"},
	{Name: "image", Label: "进程", Type: "text"},
	{Name: "user", Label: "用户", Type: "text"},
	{Name: "guid", Label: "进程GUID", Type: "text"},
	{Name: "query", Label: "域名", Type: "text"},
	{Name: "results", Label: "解析结果", Type: "text"},
	{Name: "geo", Label: "归属地", Type: "text"},
	{Name: "country", Label: "国家/地区", Type: "text"},
	{Name: "status", Label: "状态", Type: "int"},
	{Name: "rule_name", Label: "规则", Type: "text"},
	{Name: "risk", Label: "风险", Type: "text"},
}

var processFields = []FieldMeta{
	{Name: "ts", Label: "时间", Type: "time"},
	{Name: "host", Label: "主机", Type: "text"},
	{Name: "image", Label: "进程", Type: "text"},
	{Name: "pid", Label: "PID", Type: "text"},
	{Name: "user", Label: "用户", Type: "text"},
	{Name: "guid", Label: "进程GUID", Type: "text"},
	{Name: "cmdline", Label: "命令行", Type: "text"},
	{Name: "parent", Label: "父进程", Type: "text"},
	{Name: "parent_guid", Label: "父进程GUID", Type: "text"},
	{Name: "parent_pid", Label: "父PID", Type: "text"},
	{Name: "parent_cmdline", Label: "父命令行", Type: "text"},
	{Name: "integrity", Label: "完整性", Type: "text"},
	{Name: "hashes", Label: "哈希", Type: "text"},
	{Name: "rule_name", Label: "规则", Type: "text"},
	{Name: "source", Label: "来源", Type: "text"},
}

func nativeRun(cfg nativeConfig) error {
	runtime.LockOSThread()

	if _, err := win.CoInitializeEx(co.COINIT_APARTMENTTHREADED | co.COINIT_DISABLE_OLE1DDE); err != nil {
		return err
	}
	defer win.CoUninitialize()

	app := newNativeApp(cfg)
	app.build()
	app.wnd.RunAsMain()
	app.stopLive()
	return nil
}

func newNativeApp(cfg nativeConfig) *nativeApp {
	loc := cfg.loc
	if loc == nil {
		loc = time.Local
	}
	sec := cfg.config.ReadIntervalSeconds
	if sec < 1 {
		sec = 5
	}
	a := &nativeApp{
		cfg: cfg, loc: loc, fieldIdx: map[string]int{}, filterTab: 0,
		refreshEvery: time.Duration(sec) * time.Second,
		liveWake:     make(chan struct{}, 1),
		hotCache:     map[string]hotEntry{},
		procNetOnly:  true,
	}
	fields, err := cfg.db.Fields()
	if err != nil || len(fields) == 0 {
		fields = append([]FieldMeta{}, promoted...)
	}
	a.fields = fields
	for i, f := range fields {
		a.fieldIdx[f.Name] = i
	}
	return a
}

func (a *nativeApp) build() {
	winW, winH := nativeWindowSize()
	a.wnd = ui.NewMain(ui.OptsMain().
		Title(appWindowTitle).
		Size(winW, winH).
		Center(true))

	logicTexts := []string{"AND", "OR"}
	fieldTexts := make([]string, len(a.fields))
	for i, f := range a.fields {
		fieldTexts[i] = f.Label
	}
	a.cbLogic = ui.NewComboBox(a.wnd, ui.OptsComboBox().
		Position(ui.Dpi(12, 38)).
		Width(ui.DpiX(72)).
		Texts(logicTexts...).
		Select(0))
	a.cbField = ui.NewComboBox(a.wnd, ui.OptsComboBox().
		Position(ui.Dpi(92, 38)).
		Width(ui.DpiX(150)).
		Texts(fieldTexts...).
		Select(defaultFieldIndex(0, a.fields)))
	a.cbOp = ui.NewComboBox(a.wnd, ui.OptsComboBox().
		Position(ui.Dpi(248, 38)).
		Width(ui.DpiX(86)))
	a.txtValue = ui.NewEdit(a.wnd, ui.OptsEdit().
		Position(ui.Dpi(340, 38)).
		Width(ui.DpiX(300)))
	a.cbBool = ui.NewComboBox(a.wnd, ui.OptsComboBox().
		Position(ui.Dpi(340, 38)).
		Width(ui.DpiX(120)).
		Texts("是", "否").
		Select(0))
	a.lblHot = ui.NewStatic(a.wnd, ui.OptsStatic().
		Text("热门数据TOP10（点击快速筛选）").
		Position(ui.Dpi(12, 68)).
		Size(ui.Dpi(280, 20)))
	for i := 0; i < 10; i++ {
		btn := ui.NewButton(a.wnd, ui.OptsButton().
			Text("").
			Position(ui.Dpi(12, 68)).
			Width(ui.DpiX(90)).
			Height(ui.DpiY(24)))
		idx := i
		btn.On().BnClicked(func() { a.addHotValueAt(idx) })
		a.hotBtns = append(a.hotBtns, btn)
	}
	a.txtSyntax = ui.NewEdit(a.wnd, ui.OptsEdit().
		Position(ui.Dpi(58, 10)).
		Width(ui.DpiX(600)).
		Height(ui.DpiY(24)))
	a.btnApply = ui.NewButton(a.wnd, ui.OptsButton().
		Text("搜索").
		Position(ui.Dpi(600, 37)).
		Width(ui.DpiX(64)))
	a.btnAdd = ui.NewButton(a.wnd, ui.OptsButton().
		Text("添加条件").
		Position(ui.Dpi(560, 37)).
		Width(ui.DpiX(78)))
	a.btnReset = ui.NewButton(a.wnd, ui.OptsButton().
		Text("重置").
		Position(ui.Dpi(646, 37)).
		Width(ui.DpiX(64)))
	a.btnHelp = ui.NewButton(a.wnd, ui.OptsButton().
		Text("语法？").
		Position(ui.Dpi(716, 37)).
		Width(ui.DpiX(72)))
	a.btnLive = ui.NewButton(a.wnd, ui.OptsButton().
		Text("暂停读取").
		Position(ui.Dpi(12, 8)).
		Width(ui.DpiX(32)).
		CtrlStyle(co.BS_ICON))
	a.tabs = newNativeTabs(a, winW, winH)
	a.table = a.tabs.conn
	a.btnExport = ui.NewButton(a.wnd, ui.OptsButton().
		Text("导出日志").
		Position(ui.Dpi(818, 102)).
		Width(ui.DpiX(92)))
	a.chkNetOnly = ui.NewCheckBox(a.wnd, ui.OptsCheckBox().
		Text("不显示无网络连接进程").
		Position(ui.Dpi(640, 102)).
		Size(ui.Dpi(170, 24)).
		State(co.BST_CHECKED))

	a.sbar = ui.NewStatusBar(a.wnd, ui.OptsStatusBar().
		FixedPart(ui.DpiX(150), "日志总计 0 条").
		FixedPart(ui.DpiX(190), "连接日志 0 条").
		FlexPart(1, "就绪").
		FixedPart(ui.DpiX(220), ""))
	a.lblRefresh = ui.NewStatic(a.wnd, ui.OptsStatic().
		Text("读取日志频率").
		Position(ui.Dpi(12, 100)).
		Size(ui.Dpi(90, 20)))
	a.edRefresh = ui.NewEdit(a.wnd, ui.OptsEdit().
		Text(strconv.Itoa(int(a.refreshEvery/time.Second))).
		Position(ui.Dpi(54, 100)).
		Width(ui.DpiX(44)))
	a.lblSec = ui.NewStatic(a.wnd, ui.OptsStatic().
		Text("秒").
		Position(ui.Dpi(102, 100)).
		Size(ui.Dpi(20, 20)))
	a.btnTop = ui.NewButton(a.wnd, ui.OptsButton().
		Text("↑").
		Position(ui.Dpi(12, 100)).
		Width(ui.DpiX(32)).
		Height(ui.DpiY(32)).
		CtrlStyle(co.BS_FLAT))

	a.bindEvents()
}

func nativeWindowSize() (int, int) {
	sw, sh := screenWorkArea()
	scale := float64(ui.DpiX(100)) / 100.0
	w := sw - int(60*scale)
	h := sh - int(90*scale)
	maxW, maxH := int(1460*scale), int(860*scale)
	if w > maxW {
		w = maxW
	}
	if h > maxH {
		h = maxH
	}
	minW, minH := int(1000*scale), int(620*scale)
	if minW > sw-30 {
		minW = sw - 30
	}
	if minH > sh-60 {
		minH = sh - 60
	}
	if w < minW {
		w = minW
	}
	if h < minH {
		h = minH
	}
	return w, h
}

func screenWorkArea() (int, int) {
	var rc win.RECT
	if err := win.SystemParametersInfo(co.SPI_GETWORKAREA, 0, unsafe.Pointer(&rc), 0); err == nil {
		return int(rc.Right - rc.Left), int(rc.Bottom - rc.Top)
	}
	return int(win.GetSystemMetrics(co.SM_CXSCREEN)), int(win.GetSystemMetrics(co.SM_CYSCREEN))
}

func (a *nativeApp) bindEvents() {
	if brush, err := win.GetSysColorBrush(co.COLOR_BTNFACE); err == nil {
		a.wnd.On().WmCtlColorStatic(func(p ui.WmCtlColor) win.HBRUSH {
			_, _ = p.Hdc().SetBkMode(co.BKMODE_TRANSPARENT)
			return brush
		})
	}
	a.wnd.On().WmCommand(uint16(menuDataSources), co.CMD(0), func() { a.openSysmonPanel() })
	a.wnd.On().WmCommand(uint16(menuSettings), co.CMD(0), func() { a.openSettingsPanel() })
	a.wnd.On().WmCommand(uint16(menuAbout), co.CMD(0), func() { a.showAbout() })
	a.wnd.On().WmCommand(uint16(menuStats), co.CMD(0), func() { a.openStatsPanel() })
	a.wnd.On().WmCommand(uint16(menuImport), co.CMD(0), func() { a.importDialog() })
	a.btnAdd.On().BnClicked(func() { a.addCondition() })
	a.btnReset.On().BnClicked(func() { a.resetConditions() })
	a.btnHelp.On().BnClicked(func() { showSyntaxHelp(a) })
	a.btnLive.On().BnClicked(func() { a.toggleLiveReading() })
	a.btnExport.On().BnClicked(func() { a.exportDialog() })
	a.chkNetOnly.On().BnClicked(func() { a.toggleProcNetOnly() })
	a.btnApply.On().BnClicked(func() { a.applySyntax() })
	a.edRefresh.OnSubclass().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_RETURN && !p.IsReleasingKey() {
			a.applyRefreshInterval()
		}
	})
	a.edRefresh.On().EnKillFocus(func() { a.applyRefreshInterval() })
	a.btnTop.On().BnClicked(func() {
		if a.tabs != nil {
			a.tabs.scrollTop()
		}
	})

	a.txtValue.OnSubclass().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_RETURN && !p.IsReleasingKey() {
			a.addCondition()
		}
	})
	a.cbField.On().CbnSelChange(func() {
		a.updateOperators()
		a.refreshHotValues()
	})
	a.cbLogic.On().CbnDropDown(func() {})
	a.cbField.On().CbnDropDown(func() {
		a.cbField.Hwnd().PostMessage(co.WM(co.CB_SETTOPINDEX), 0, 0)
	})
	a.cbOp.On().CbnDropDown(func() {})
	a.cbBool.On().CbnDropDown(func() {})
	a.txtSyntax.OnSubclass().WmKeyDown(func(p ui.WmKey) {
		if p.IsReleasingKey() {
			return
		}
		switch p.VirtualKeyCode() {
		case co.VK_RETURN:
			a.applySyntax()
		}
	})

	a.wnd.On().WmCreate(func(_ ui.WmCreate) int {
		winsh.DragAcceptFiles(a.wnd.Hwnd(), true)
		a.buildMenu()
		a.layout()
		a.sbar.Hwnd().SendMessage(co.SB_SETMINHEIGHT, win.WPARAM(ui.DpiY(28)), 0)
		a.sbar.Hwnd().SendMessage(co.WM_SIZE, 0, 0)
		a.table.fitTimeColumn()
		if a.tabs != nil {
			a.tabs.fitTimeColumns()
		}
		setCueText(a.txtSyntax.Hwnd(), syntaxCueForTab(0))
		a.initLiveButtonIcons()
		a.syncLiveButton()
		a.updateOperators()
		a.refreshHotValues()
		a.sbar.Part(2).SetText("就绪")
		a.table.setSortArrow(1, true)
		a.table.reload("", "ts", true)
		a.refreshFixedCount()
		_ = a.wnd.Hwnd().SetTimer(timerLive, 1500)
		go func() {
			time.Sleep(350 * time.Millisecond)
			a.wnd.UiThread(a.autoSetupSysmon)
		}()
		return 0
	})
	a.wnd.On().WmSize(func(_ ui.WmSize) {
		a.layout()
	})
	a.wnd.On().WmGetMinMaxInfo(func(p ui.WmGetMinMaxInfo) {
		info := p.Info()
		minW, minH := ui.DpiX(980), ui.DpiY(620)
		if sw, sh := screenWorkArea(); minW > sw-30 || minH > sh-60 {
			if minW > sw-30 {
				minW = sw - 30
			}
			if minH > sh-60 {
				minH = sh - 60
			}
		}
		info.PtMinTrackSize = win.POINT{X: int32(minW), Y: int32(minH)}
	})
	a.wnd.On().WmTimer(timerLive, func() { a.onLiveTimer() })
	a.wnd.On().Wm(wmAppRedraw, func(_ ui.Wm) uintptr {
		if a.table != nil && a.table.lv.Hwnd() != 0 {
			a.table.lv.Hwnd().InvalidateRect(nil, true)
		}
		return 0
	})
	a.wnd.On().WmDropFiles(func(p ui.WmDropFiles) {
		hDrop := p.HDrop()
		files, err := hDrop.DragQueryFile()
		hDrop.DragFinish()
		if err != nil || len(files) == 0 {
			a.setStatus("没有收到可导入的文件")
			return
		}
		a.importPaths(files)
	})
	a.wnd.On().WmClose(func() {
		_ = a.wnd.Hwnd().KillTimer(timerLive)
		a.stopLive()
		_ = a.wnd.Hwnd().DestroyWindow()
	})
	a.wnd.On().WmDestroy(func() {
		if a.icoPlay != 0 {
			_ = a.icoPlay.DestroyIcon()
			a.icoPlay = 0
		}
		if a.icoPause != 0 {
			_ = a.icoPause.DestroyIcon()
			a.icoPause = 0
		}
	})
}

func (a *nativeApp) layout() {
	hWnd := a.wnd.Hwnd()
	if hWnd == 0 {
		return
	}
	// 任一下拉框展开时跳过整次布局：Win32 会把悬停中的选项提交为选中值
	// （热词后台刷新触发重排的场景）。下拉关闭后的下一轮刷新会补上布局。
	for _, cb := range []*ui.ComboBox{a.cbLogic, a.cbField, a.cbOp, a.cbBool} {
		if cb == nil || cb.Hwnd() == 0 {
			continue
		}
		if dropped, _ := cb.Hwnd().SendMessage(co.CB_GETDROPPEDSTATE, 0, 0); dropped != 0 {
			return
		}
	}
	rc, err := hWnd.GetClientRect()
	if err != nil {
		return
	}
	w := int(rc.Right - rc.Left)
	h := int(rc.Bottom - rc.Top)
	margin := ui.DpiX(12)
	gap := ui.DpiX(6)
	statusMinH := ui.DpiY(28)
	bottomH := statusMinH + ui.DpiY(2)
	tableY := ui.DpiY(156)

	btnExportW := ui.DpiX(92)
	btnApplyW := ui.DpiX(64)
	btnResetW := ui.DpiX(64)
	btnHelpW := ui.DpiX(72)
	btnAddW := ui.DpiX(78)
	btnLiveW := ui.DpiX(32)

	// 第一行：完整语法表达式。
	setBounds(a.btnLive.Hwnd(), margin, ui.DpiY(9), btnLiveW, ui.DpiY(25))
	syntaxX := margin + btnLiveW + gap
	controlsW := gap + btnApplyW + gap + btnResetW + gap + btnHelpW
	syntaxW := w - margin - syntaxX - controlsW
	if syntaxW > ui.DpiX(920) {
		syntaxW = ui.DpiX(920)
	}
	if syntaxW < ui.DpiX(220) {
		syntaxW = ui.DpiX(220)
	}
	searchX := syntaxX + syntaxW + gap
	resetX := searchX + btnApplyW + gap
	helpX := resetX + btnResetW + gap
	rowRight := helpX + btnHelpW
	setBounds(a.btnApply.Hwnd(), searchX, ui.DpiY(9), btnApplyW, ui.DpiY(25))
	setBounds(a.btnReset.Hwnd(), resetX, ui.DpiY(9), btnResetW, ui.DpiY(25))
	setBounds(a.btnHelp.Hwnd(), helpX, ui.DpiY(9), btnHelpW, ui.DpiY(25))
	setBounds(a.txtSyntax.Hwnd(), syntaxX, ui.DpiY(10), syntaxW, ui.DpiY(24))

	// 第二行：条件快捷添加。
	narrow := w < ui.DpiX(1180)
	logicW, fieldW := ui.DpiX(72), ui.DpiX(150)
	opW := ui.DpiX(86)
	if narrow {
		logicW, fieldW, opW = ui.DpiX(58), ui.DpiX(115), ui.DpiX(70)
	}
	valueX := margin + logicW + gap + fieldW + gap + opW + gap
	addX := rowRight - btnAddW
	valueW := addX - gap - valueX
	if valueW < ui.DpiX(120) {
		valueW = ui.DpiX(120)
	}
	setBounds(a.btnAdd.Hwnd(), addX, ui.DpiY(40), btnAddW, ui.DpiY(25))
	setBounds(a.cbLogic.Hwnd(), margin, ui.DpiY(40), logicW, ui.DpiY(160))
	setBounds(a.cbField.Hwnd(), margin+logicW+gap, ui.DpiY(40), fieldW, ui.DpiY(320))
	setBounds(a.cbOp.Hwnd(), margin+logicW+gap+fieldW+gap, ui.DpiY(40), opW, ui.DpiY(160))
	idx := a.cbField.SelectedIndex()
	fields := a.activeFields()
	isBool := idx >= 0 && idx < len(fields) && fields[idx].Type == "bool"
	if isBool {
		showCtrl(a.txtValue.Hwnd(), false)
		showCtrl(a.cbBool.Hwnd(), true)
		setBounds(a.cbBool.Hwnd(), valueX, ui.DpiY(40), ui.DpiX(120), ui.DpiY(160))
	} else {
		showCtrl(a.cbBool.Hwnd(), false)
		showCtrl(a.txtValue.Hwnd(), true)
		setBounds(a.txtValue.Hwnd(), valueX, ui.DpiY(40), valueW, ui.DpiY(24))
	}

	// 第三行：热门词按钮，点一下即加入表达式。
	setBounds(a.lblHot.Hwnd(), margin, ui.DpiY(68), ui.DpiX(280), ui.DpiY(20))
	hotX := margin
	hotRight := w - margin
	hotY := ui.DpiY(94)
	for i, btn := range a.hotBtns {
		if i >= len(a.hotValues) {
			showCtrl(btn.Hwnd(), false)
			continue
		}
		value := a.hotValues[i]
		count := 0
		if i < len(a.hotCounts) {
			count = a.hotCounts[i]
		}
		countText := commaInt(count)
		suffix := fmt.Sprintf(" (%s)", countText)
		measure, done := textMeasurer(btn.Hwnd())
		valueW := 0
		suffixW := 0
		if measure != nil {
			valueW = measure(value)
			suffixW = measure(suffix)
		}
		if valueW <= 0 || suffixW <= 0 {
			valueW = ui.DpiX(len([]rune(value)) * 8)
			suffixW = ui.DpiX(len(countText)*8 + 12)
		}
		padW := ui.DpiX(22)
		bw := valueW + suffixW + padW
		if bw < ui.DpiX(80) {
			bw = ui.DpiX(80)
		}
		if bw > ui.DpiX(300) {
			bw = ui.DpiX(300)
		}
		displayValue := value
		valueAvail := bw - suffixW - padW
		if valueAvail < ui.DpiX(16) {
			valueAvail = ui.DpiX(16)
		}
		if valueW > valueAvail {
			runes := []rune(value)
			best := "…"
			lo, hi := 1, len(runes)-1
			for lo <= hi {
				keep := (lo + hi) / 2
				cand := "…" + string(runes[len(runes)-keep:])
				cw := ui.DpiX(len([]rune(cand)) * 8)
				if measure != nil {
					if w := measure(cand); w > 0 {
						cw = w
					}
				}
				if cw <= valueAvail {
					best = cand
					lo = keep + 1
				} else {
					hi = keep - 1
				}
			}
			displayValue = best
		}
		if done != nil {
			done()
		}
		text := displayValue + suffix
		if hotX+bw > hotRight {
			hotX = margin
			hotY += ui.DpiY(28)
		}
		if hotY+ui.DpiY(24) > ui.DpiY(148) {
			showCtrl(btn.Hwnd(), false)
			continue
		}
		btn.SetText(text)
		setBounds(btn.Hwnd(), hotX, hotY, bw, ui.DpiY(24))
		showCtrl(btn.Hwnd(), true)
		hotX += bw + gap
	}

	tableH := h - tableY - bottomH - ui.DpiY(8)
	if tableH < ui.DpiY(120) {
		tableH = ui.DpiY(120)
	}
	if a.tabs != nil {
		setBounds(a.tabs.tab.Hwnd(), margin, tableY, w-margin*2, tableH)
		a.tabs.resizeContent()
	}
	chkNetW := ui.DpiX(170)
	setBounds(a.chkNetOnly.Hwnd(), w-margin-btnExportW-gap-chkNetW, tableY+ui.DpiY(1), chkNetW, ui.DpiY(24))
	a.syncProcNetCheckbox()
	setBounds(a.btnExport.Hwnd(), w-margin-btnExportW, tableY+ui.DpiY(1), btnExportW, ui.DpiY(24))
	a.btnExport.Hwnd().SetWindowPos(win.HWND(0),
		win.POINT{}, win.SIZE{},
		co.SWP_NOMOVE|co.SWP_NOSIZE|co.SWP_NOACTIVATE)

	// 悬浮按钮固定在表格右下角，滚动后一键回到第一条。
	topW := ui.DpiX(32)
	topH := ui.DpiY(32)
	topX := w - margin - ui.DpiX(24) - topW
	topY := tableY + tableH - topH - ui.DpiY(26)
	setBounds(a.btnTop.Hwnd(), topX, topY, topW, topH)
	a.btnTop.Hwnd().SetWindowPos(win.HWND(0),
		win.POINT{}, win.SIZE{},
		co.SWP_NOMOVE|co.SWP_NOSIZE|co.SWP_NOACTIVATE)

	statusTop := h - statusMinH
	secW := ui.DpiX(20)
	edW := ui.DpiX(44)
	lblW := ui.DpiX(90)
	lblH := ui.DpiY(22)
	labelY := statusTop + (statusMinH-lblH)/2
	labelY += ui.DpiY(2)
	editH := ui.DpiY(22)
	editY := statusTop + (statusMinH-editH)/2
	refreshAreaW := ui.DpiX(220)
	refreshGroupW := lblW + gap + edW + gap + secW
	refreshX := w - refreshAreaW + (refreshAreaW-refreshGroupW)/2
	setBounds(a.lblRefresh.Hwnd(), refreshX, labelY, lblW, lblH)
	refreshX += lblW + gap
	setBounds(a.edRefresh.Hwnd(), refreshX, editY, edW, editH)
	refreshX += edW + gap
	setBounds(a.lblSec.Hwnd(), refreshX, labelY, secW, lblH)
	for _, h := range []win.HWND{a.lblRefresh.Hwnd(), a.edRefresh.Hwnd(), a.lblSec.Hwnd()} {
		h.SetWindowPos(win.HWND(0), win.POINT{}, win.SIZE{},
			co.SWP_NOMOVE|co.SWP_NOSIZE|co.SWP_NOACTIVATE)
		h.InvalidateRect(nil, true)
		h.UpdateWindow()
	}
}

func (a *nativeApp) buildMenu() {
	menu, err := win.CreateMenu()
	if err != nil {
		return
	}
	config, err := win.CreatePopupMenu()
	if err != nil {
		return
	}
	appendMenuItem(config, 0, menuDataSources, "日志源管理", 0)
	appendMenuItem(config, 1, menuSettings, "数据与保留设置", 0)
	appendMenuItem(menu, 0, 100, "配置", config)
	appendMenuItem(menu, 1, menuStats, "数据统计", 0)
	appendMenuItem(menu, 2, menuImport, "导入日志", 0)
	appendMenuItem(menu, 3, menuAbout, "关于", 0)
	_ = a.wnd.Hwnd().SetMenu(menu)
	if h, _, _ := procCreateSolidBrush.Call(uintptr(win.GetSysColor(co.COLOR_BTNFACE))); h != 0 {
		brush := win.HBRUSH(h)
		var mi win.MENUINFO
		mi.SetCbSize()
		mi.FMask = co.MIM_BACKGROUND
		mi.HbrBack = brush
		_ = menu.SetMenuInfo(&mi)
		_ = config.SetMenuInfo(&mi)
	}
	_ = a.wnd.Hwnd().DrawMenuBar()
	_ = a.wnd.Hwnd().RedrawWindow(nil, 0, co.RDW_FRAME|co.RDW_INVALIDATE|co.RDW_UPDATENOW)
}

func appendMenuItem(menu win.HMENU, pos int, id uint16, text string, submenu win.HMENU) {
	utf16, _ := syscall.UTF16FromString(text)
	var mii win.MENUITEMINFO
	mii.SetCbSize()
	mii.FMask = co.MIIM_ID | co.MIIM_STRING
	mii.WId = uint32(id)
	mii.DwTypeData = &utf16[0]
	mii.Cch = uint32(len(utf16) - 1)
	if submenu != 0 {
		mii.FMask |= co.MIIM_SUBMENU
		mii.HSubMenu = submenu
	}
	_ = menu.InsertMenuItemByPos(pos, &mii)
}

func (a *nativeApp) showAbout() {
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("关于 N-trace").
		Size(ui.Dpi(440, 238)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	ui.NewStatic(modal, ui.OptsStatic().
		Text("N-trace 联网安全审计").
		Position(ui.Dpi(20, 24)).
		Size(ui.Dpi(400, 22)).
		CtrlStyle(co.SS_CENTER|co.SS_CENTERIMAGE))
	ui.NewStatic(modal, ui.OptsStatic().
		Text("洞察终端恶意非法外联").
		Position(ui.Dpi(20, 50)).
		Size(ui.Dpi(400, 22)).
		CtrlStyle(co.SS_CENTER|co.SS_CENTERIMAGE))
	ui.NewStatic(modal, ui.OptsStatic().
		Text("版本：1.0").
		Position(ui.Dpi(20, 76)).
		Size(ui.Dpi(400, 22)).
		CtrlStyle(co.SS_CENTER|co.SS_CENTERIMAGE))
	ui.NewStatic(modal, ui.OptsStatic().
		Text("作者：stu0lea").
		Position(ui.Dpi(20, 102)).
		Size(ui.Dpi(400, 22)).
		CtrlStyle(co.SS_CENTER|co.SS_CENTERIMAGE))
	ghLabel := ui.NewStatic(modal, ui.OptsStatic().
		Text("GitHub：").
		Position(ui.Dpi(60, 128)).
		Size(ui.Dpi(60, 22)).
		CtrlStyle(co.SS_LEFT|co.SS_CENTERIMAGE))
	link := ui.NewStatic(modal, ui.OptsStatic().
		Text("https://github.com/stu0lea/n-trace").
		Position(ui.Dpi(120, 128)).
		Size(ui.Dpi(260, 22)).
		CtrlStyle(co.SS_LEFT|co.SS_CENTERIMAGE|co.SS_NOTIFY))
	link.On().StnClicked(func() {
		openBrowser("https://github.com/stu0lea/n-trace")
	})

	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(175, 174)).
		Width(ui.DpiX(90)))
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	brush, _ := win.GetSysColorBrush(co.COLOR_BTNFACE)
	modal.On().WmCtlColorStatic(func(p ui.WmCtlColor) win.HBRUSH {
		_, _ = p.Hdc().SetBkMode(co.BKMODE_TRANSPARENT)
		if p.HwndControl() == link.Hwnd() {
			_, _ = p.Hdc().SetTextColor(win.COLORREF(0x00C00000))
		} else {
			_, _ = p.Hdc().SetTextColor(0)
		}
		return brush
	})
	modal.On().WmCreate(func(_ ui.WmCreate) int {
		labelW, linkW := ui.DpiX(58), ui.DpiX(250)
		if measure, done := textMeasurer(ghLabel.Hwnd()); measure != nil {
			labelW = measure("GitHub：")
			done()
		}
		if measure, done := textMeasurer(link.Hwnd()); measure != nil {
			linkW = measure("https://github.com/stu0lea/n-trace")
			done()
		}
		rc, err := modal.Hwnd().GetClientRect()
		if err != nil {
			return 0
		}
		labelBoxW, linkBoxW := labelW+2, linkW+4
		x := (int(rc.Right-rc.Left) - labelBoxW - linkBoxW) / 2
		if x < ui.DpiX(20) {
			x = ui.DpiX(20)
		}
		setBounds(ghLabel.Hwnd(), x, ui.DpiY(140), labelBoxW, ui.DpiY(22))
		setBounds(link.Hwnd(), x+labelBoxW, ui.DpiY(140), linkBoxW, ui.DpiY(22))
		return 0
	})
	modal.ShowModal()
}

func showCtrl(h win.HWND, visible bool) {
	if h == 0 {
		return
	}
	if visible {
		h.ShowWindow(co.SW_SHOW)
	} else {
		h.ShowWindow(co.SW_HIDE)
	}
}

func setCueText(h win.HWND, text string) {
	if h == 0 {
		return
	}
	p, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	h.SendMessage(co.EM_SETCUEBANNER, 1, win.LPARAM(unsafe.Pointer(p)))
}

func defaultFieldIndex(tab int, fields []FieldMeta) int {
	name := "dst_ip"
	switch tab {
	case 1:
		name = "image"
	case 2:
		name = "query"
	}
	for i, f := range fields {
		if f.Name == name {
			return i
		}
	}
	return 0
}

func setBounds(h win.HWND, x, y, w, hgt int) {
	if h == 0 || w <= 0 || hgt <= 0 {
		return
	}
	// 位置尺寸都没变时跳过 SetWindowPos：
	// 重复移动控件会关闭展开中的下拉框（热词后台刷新场景）。
	if rc, err := h.GetWindowRect(); err == nil {
		if parent, perr := h.GetParent(); perr == nil {
			_ = parent.ScreenToClientRc(&rc)
			if int(rc.Left) == x && int(rc.Top) == y &&
				int(rc.Right-rc.Left) == w && int(rc.Bottom-rc.Top) == hgt {
				return
			}
		}
	}
	h.SetWindowPos(0,
		win.POINT{X: int32(x), Y: int32(y)},
		win.SIZE{Cx: int32(w), Cy: int32(hgt)},
		co.SWP_NOZORDER|co.SWP_NOACTIVATE)
}

func textMeasurer(h win.HWND) (func(string) int, func()) {
	if h == 0 {
		return nil, nil
	}
	hdc, err := h.GetDC()
	if err != nil {
		return nil, nil
	}
	var prev win.HFONT
	if hfont, _ := h.SendMessage(co.WM_GETFONT, 0, 0); hfont != 0 {
		prev, _ = hdc.SelectObjectFont(win.HFONT(hfont))
	}
	measure := func(text string) int {
		sz, err := hdc.GetTextExtentPoint32(text)
		if err != nil {
			return 0
		}
		return int(sz.Cx)
	}
	done := func() {
		if prev != 0 {
			hdc.SelectObjectFont(prev)
		}
		h.ReleaseDC(hdc)
	}
	return measure, done
}

func (a *nativeApp) setStatus(msg string) {
	if a.sbar != nil {
		a.sbar.Part(2).SetText(msg)
	}
}

func (a *nativeApp) applyRefreshInterval() {
	s := strings.TrimSpace(a.edRefresh.Text())
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 3600 {
		a.setStatus("刷新间隔需为 1–3600 秒")
		a.edRefresh.SetText(strconv.Itoa(int(a.refreshEvery / time.Second)))
		return
	}
	a.refreshEvery = time.Duration(n) * time.Second
	a.cfg.config.ReadIntervalSeconds = n
	_ = a.cfg.config.save(a.cfg.dataDir)
	select {
	case a.liveWake <- struct{}{}:
	default:
	}
	a.setStatus(fmt.Sprintf("刷新间隔：%d 秒", n))
}

// procQueryExpr 将“不显示无网络连接进程”勾选条件注入进程查询表达式。
func (a *nativeApp) procQueryExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	if !a.procNetOnly {
		return expr
	}
	if expr == "" {
		return "n>0"
	}
	return "(" + expr + ") and n>0"
}

func (a *nativeApp) syncProcNetCheckbox() {
	if a.chkNetOnly == nil {
		return
	}
	showCtrl(a.chkNetOnly.Hwnd(), a.tabs != nil && a.tabs.active == 1)
}

func (a *nativeApp) toggleProcNetOnly() {
	a.procNetOnly = a.chkNetOnly.IsChecked()
	if a.tabs != nil && a.tabs.active == 1 {
		a.tabs.procTable.reload(strings.TrimSpace(a.tabs.procExpr), a.tabs.procSort, a.tabs.procDesc)
		a.refreshFixedCount()
		a.refreshHotValues()
	}
}

// refreshHotValuesOnData 数据变化后节流刷新热词（热词为全局 TOP 值，与筛选无关）。
func (a *nativeApp) refreshHotValuesOnData() {
	if time.Since(a.hotLast) < 2*time.Second {
		return
	}
	a.hotLast = time.Now()
	a.refreshHotValuesKeep()
}

func (a *nativeApp) refreshFixedCount() {
	if a.sbar == nil {
		return
	}
	tab := 0
	label := "连接日志"
	if a.tabs != nil {
		tab = a.tabs.active
	}
	switch tab {
	case 1:
		label = "进程"
	case 2:
		label = "DNS"
	}
	expr := strings.TrimSpace(a.activeExpr())
	filtered := expr != ""
	a.applyCachedFixedCount(tab, filtered)
	a.fixedCountGen++
	gen := a.fixedCountGen
	go func() {
		totals, totalsErr := a.cfg.db.LogTotals()
		var total int
		var err error
		switch tab {
		case 1:
			total, err = a.cfg.db.CountProcessesFiltered(a.procQueryExpr(expr))
		case 2:
			total, err = a.cfg.db.CountDNSFiltered(expr)
		default:
			total, err = a.cfg.db.Count(expr)
		}
		a.wnd.UiThread(func() {
			if gen != a.fixedCountGen || a.sbar == nil {
				return
			}
			if totalsErr == nil {
				a.logTotals = *totals
				a.logTotalsReady = true
				all := totals.Connections + totals.Processes + totals.DNS
				a.sbar.Part(0).SetText(fmt.Sprintf("日志总计 %s 条", commaInt(all)))
			}
			if err == nil {
				if filtered {
					label = "筛选" + label
				}
				a.sbar.Part(1).SetText(fmt.Sprintf("%s %s 条", label, commaInt(total)))
			}
		})
	}()
}

func (a *nativeApp) applyCachedFixedCount(tab int, filtered bool) {
	if a.sbar == nil {
		return
	}
	if a.logTotalsReady {
		all := a.logTotals.Connections + a.logTotals.Processes + a.logTotals.DNS
		a.sbar.Part(0).SetText(fmt.Sprintf("日志总计 %s 条", commaInt(all)))
	}
	total := 0
	switch tab {
	case 1:
		if a.tabs != nil && a.tabs.procTable != nil {
			total = a.tabs.procTable.totalCount()
		}
	case 2:
		if a.tabs != nil && a.tabs.dnsTable != nil {
			total = a.tabs.dnsTable.totalCount()
		}
	default:
		if a.table != nil {
			total = a.table.totalCount()
		}
	}
	label := "连接日志"
	switch tab {
	case 1:
		label = "进程"
	case 2:
		label = "DNS"
	}
	if filtered {
		label = "筛选" + label
	}
	a.sbar.Part(1).SetText(fmt.Sprintf("%s %s 条", label, commaInt(total)))
}

func (a *nativeApp) setBusy(delta int) {
	a.busy += delta
	if a.busy < 0 {
		a.busy = 0
	}
}

// conditionExpr 把一条界面条件翻译成现有检索语法。
func conditionExpr(c filterCond) (string, error) {
	v := strings.TrimSpace(c.value)
	if v == "" {
		return "", fmt.Errorf("请输入筛选值")
	}
	field := c.field.Name
	op := c.op
	switch c.field.Type {
	case "bool":
		if b := normBool(v); b == "1" || b == "0" {
			return field + "=" + b, nil
		}
	case "int":
		if !validOp(op, "=", "!=", ">", "<", ">=", "<=") {
			op = "="
		}
		return field + op + v, nil
	case "time":
		if _, ok := parseTimeValue(v); ok {
			if !validOp(op, ">=", "<=") {
				op = ">="
			}
			return field + op + quoteExprValue(v), nil
		}
		return "", fmt.Errorf("时间格式应为 2006-01-02 15:04:05 或 2006-01-02")
	}
	if !validOp(op, ":", "!:", "=", "!=") {
		op = ":"
	}
	return field + op + quoteExprValue(v), nil
}

func validOp(op string, allowed ...string) bool {
	for _, a := range allowed {
		if op == a {
			return true
		}
	}
	return false
}

type opChoice struct {
	label string
	code  string
}

func opsFor(meta FieldMeta) []opChoice {
	switch meta.Type {
	case "int":
		return []opChoice{{"等于", "="}, {"不等于", "!="}, {"大于", ">"}, {"小于", "<"}, {"大于等于", ">="}, {"小于等于", "<="}}
	case "bool":
		return []opChoice{{"等于", "="}}
	case "time":
		return []opChoice{{">=", ">="}, {"<=", "<="}}
	default:
		return []opChoice{{"包含", ":"}, {"不包含", "!:"}, {"等于", "="}, {"不等于", "!="}}
	}
}

func (a *nativeApp) updateOperators() {
	fields := a.activeFields()
	idx := a.cbField.SelectedIndex()
	if idx < 0 || idx >= len(fields) {
		return
	}
	meta := fields[idx]
	ops := opsFor(meta)
	labels := make([]string, len(ops))
	for i, op := range ops {
		labels[i] = op.label
	}
	a.cbOp.DeleteAllItems()
	a.cbOp.AddItem(labels...)
	a.cbOp.SelectIndex(0)
	if meta.Type == "bool" {
		vals := boolChoices(meta)
		a.cbBool.DeleteAllItems()
		a.cbBool.AddItem(vals...)
		a.cbBool.SelectIndex(0)
	}
	a.wnd.UiThread(a.layout)
}

func (a *nativeApp) selectedOp() string {
	fields := a.activeFields()
	idx := a.cbField.SelectedIndex()
	if idx < 0 || idx >= len(fields) {
		return ""
	}
	ops := opsFor(fields[idx])
	sel := a.cbOp.SelectedIndex()
	if sel < 0 || sel >= len(ops) {
		if len(ops) > 0 {
			return ops[0].code
		}
		return ""
	}
	return ops[sel].code
}

func boolChoices(meta FieldMeta) []string {
	switch meta.Name {
	case "outbound":
		return []string{"出站", "入站"}
	case "public":
		return []string{"外网", "内网"}
	case "ipv6":
		return []string{"是", "否"}
	default:
		return []string{"是", "否"}
	}
}

// hotCacheTTL 热词缓存有效期；有效期内不再对整表做 GROUP BY，
// 数据驱动的节流刷新也只读缓存，避免大库时反复全表聚合。
const hotCacheTTL = time.Minute

type hotEntry struct {
	vals []Count
	at   time.Time
}

// hotCacheKey 缓存键：Tab + 字段名 + 进程“仅显示有网络连接进程”开关。
func hotCacheKey(tab int, field string, netOnly bool) string {
	return strconv.Itoa(tab) + "|" + field + "|" + strconv.FormatBool(netOnly)
}

// hotEntryFresh 判断缓存条目是否仍在有效期内。
func hotEntryFresh(e hotEntry, now time.Time) bool {
	return now.Sub(e.at) < hotCacheTTL
}

// refreshHotValues 清空后刷新热词（切换字段、重置等场景）。
func (a *nativeApp) refreshHotValues() { a.refreshHotValuesMode(true) }

// refreshHotValuesKeep 不清空现有热词、查询完成后原地更新数字，
// 数据驱动刷新专用，避免按钮整行隐藏再显示造成闪烁。
func (a *nativeApp) refreshHotValuesKeep() { a.refreshHotValuesMode(false) }

func (a *nativeApp) refreshHotValuesMode(clear bool) {
	fields := a.activeFields()
	idx := a.cbField.SelectedIndex()
	if idx < 0 || idx >= len(fields) {
		return
	}
	meta := fields[idx]
	if meta.Type == "bool" || meta.Type == "time" {
		if clear {
			a.hotValues = nil
			a.hotCounts = nil
			a.wnd.UiThread(a.layout)
		}
		return
	}
	key := hotCacheKey(a.filterTab, meta.Name, a.procNetOnly)
	entry, cached := a.hotCache[key]
	a.hotGen++
	gen := a.hotGen

	// 有缓存（含过期）先显示，既避免闪烁也保证切换字段时立刻有内容。
	if cached {
		a.applyHotValues(entry.vals)
		a.wnd.UiThread(a.layout)
	} else if clear {
		a.hotValues = nil
		a.hotCounts = nil
		a.wnd.UiThread(a.layout)
	}
	if cached && hotEntryFresh(entry, time.Now()) {
		return
	}
	go func() {
		var vals []Count
		var err error
		switch a.filterTab {
		case 1:
			vals, err = a.cfg.db.ProcessValuesFiltered(meta.Name, 10, a.procNetOnly)
		case 2:
			vals, err = a.cfg.db.DNSValues(meta.Name, 10)
		default:
			vals, err = a.cfg.db.Values(meta.Name, 10)
		}
		if err != nil {
			return // 查询失败时保留旧热词
		}
		a.hotCache[key] = hotEntry{vals: vals, at: time.Now()}
		a.wnd.UiThread(func() {
			if gen != a.hotGen {
				return
			}
			a.applyHotValues(vals)
			a.layout()
		})
	}()
}

func (a *nativeApp) applyHotValues(vals []Count) {
	a.hotValues = nil
	a.hotCounts = nil
	for _, v := range vals {
		if strings.TrimSpace(v.Key) != "" && len(a.hotValues) < 10 {
			a.hotValues = append(a.hotValues, v.Key)
			a.hotCounts = append(a.hotCounts, v.N)
		}
	}
}

func (a *nativeApp) addHotValueAt(idx int) {
	if idx >= 0 && idx < len(a.hotValues) {
		a.addHotValue(a.hotValues[idx])
	}
}

func (a *nativeApp) addHotValue(value string) {
	fields := a.activeFields()
	idx := a.cbField.SelectedIndex()
	if idx < 0 || idx >= len(fields) {
		return
	}
	logic := "OR"
	// 点选热词按精确匹配处理，不跟随当前下拉框选择的运算符。
	c := filterCond{logic: logic, field: fields[idx], op: "=", value: value}
	expr, err := conditionExpr(c)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	current := strings.TrimSpace(a.txtSyntax.Text())
	if current == "" {
		a.txtSyntax.SetText(expr)
	} else {
		a.txtSyntax.SetText(current + " " + logic + " " + expr)
	}
	a.applySyntax()
}

func quoteExprValue(v string) string {
	v = strings.ReplaceAll(v, `"`, "")
	if strings.ContainsAny(v, " \t\n\r()|") {
		return `"` + v + `"`
	}
	return v
}

func (a *nativeApp) addCondition() {
	fields := a.activeFields()
	idx := a.cbField.SelectedIndex()
	if idx < 0 || idx >= len(fields) {
		return
	}
	meta := fields[idx]
	value := strings.TrimSpace(a.txtValue.Text())
	if meta.Type == "bool" {
		value = strings.TrimSpace(a.cbBool.CurrentText())
	}
	if value == "" {
		a.setStatus("请输入筛选值")
		a.txtValue.Focus()
		return
	}
	logic := strings.ToUpper(a.cbLogic.CurrentText())
	if logic != "OR" {
		logic = "AND"
	}
	c := filterCond{logic: logic, field: meta, op: a.selectedOp(), value: value}
	expr, err := conditionExpr(c)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	current := strings.TrimSpace(a.txtSyntax.Text())
	if current == "" {
		a.txtSyntax.SetText(expr)
	} else {
		a.txtSyntax.SetText(current + " " + logic + " " + expr)
	}
	if meta.Type != "bool" {
		a.txtValue.SetText("")
	}
	a.focusSyntax()
	a.setStatus("条件已加入表达式，点「应用」或按 Enter 检索")
}

func (a *nativeApp) applySyntax() {
	expr := strings.TrimSpace(a.txtSyntax.Text())
	if a.tabs != nil && a.tabs.active == 1 {
		a.setStatus("正在校验进程筛选语法…")
		go func() {
			_, _, err := a.cfg.db.compileProcess(expr)
			a.wnd.UiThread(func() {
				if err != nil {
					a.setStatus("进程语法错误：" + err.Error())
					a.txtSyntax.Focus()
					return
				}
				a.tabs.procExpr = expr
				a.refreshProcesses()
				a.refreshFixedCount()
			})
		}()
		return
	}
	if a.tabs != nil && a.tabs.active == 2 {
		a.setStatus("正在校验 DNS 筛选语法…")
		go func() {
			_, _, err := a.cfg.db.compileDNS(expr)
			a.wnd.UiThread(func() {
				if err != nil {
					a.setStatus("DNS 语法错误：" + err.Error())
					a.txtSyntax.Focus()
					return
				}
				a.tabs.dnsExpr = expr
				a.refreshDNS()
				a.refreshFixedCount()
			})
		}()
		return
	}
	a.setStatus("正在校验语法…")
	go func() {
		_, _, err := a.cfg.db.compile(expr)
		a.wnd.UiThread(func() {
			if err != nil {
				a.setStatus("语法错误：" + err.Error())
				a.txtSyntax.Focus()
				return
			}
			a.table.reload(expr, a.table.currentSort(), a.table.currentDesc())
			if a.tabs != nil {
				a.tabs.refreshAfterFilter()
			}
		})
	}()
}

func (a *nativeApp) focusSyntax() {
	a.txtSyntax.Focus()
}

func (a *nativeApp) syncSyntaxForTab(idx int) {
	if a.tabs == nil || a.txtSyntax == nil {
		return
	}
	if idx == 1 {
		a.txtSyntax.SetText(a.tabs.procExpr)
		setCueText(a.txtSyntax.Hwnd(), syntaxCueForTab(1))
		a.syncFilterFields()
		return
	}
	if idx == 2 {
		a.txtSyntax.SetText(a.tabs.dnsExpr)
		setCueText(a.txtSyntax.Hwnd(), syntaxCueForTab(2))
		a.syncFilterFields()
		return
	}
	if a.table == nil {
		return
	}
	a.txtSyntax.SetText(a.table.currentExpr())
	setCueText(a.txtSyntax.Hwnd(), syntaxCueForTab(0))
	a.syncFilterFields()
}

func syntaxCueForTab(idx int) string {
	switch idx {
	case 1:
		return `进程检索：全局搜索或编写搜索语法，示例：image:*chrome.exe`
	case 2:
		return `DNS 检索：全局搜索或编写搜索语法，示例：query:example.com`
	default:
		return `连接检索：全局搜索或编写搜索语法，示例：dst_ip:203.0.113.10 and dst_port=443`
	}
}

func (a *nativeApp) activeFields() []FieldMeta {
	if a.tabs != nil {
		switch a.tabs.active {
		case 1:
			return processFields
		case 2:
			return dnsFields
		}
	}
	return a.fields
}

func (a *nativeApp) syncFilterFields() {
	if a.cbField == nil {
		return
	}
	tab := 0
	if a.tabs != nil {
		tab = a.tabs.active
	}
	if a.filterTab == tab && a.cbField.ItemCount() > 0 {
		return
	}
	a.filterTab = tab
	fields := a.activeFields()
	labels := make([]string, len(fields))
	for i, f := range fields {
		labels[i] = f.Label
	}
	a.cbField.DeleteAllItems()
	a.cbField.AddItem(labels...)
	a.cbField.SelectIndex(defaultFieldIndex(tab, fields))
	a.updateOperators()
	a.refreshHotValues()
}

func (a *nativeApp) appendSyntax(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	cur := strings.TrimSpace(a.txtSyntax.Text())
	switch text {
	case "AND", "OR", "NOT":
		if cur != "" {
			cur += " "
		}
		cur += text + " "
	default:
		if cur != "" {
			cur += " "
		}
		cur += text
	}
	a.txtSyntax.SetText(cur)
	a.txtSyntax.Focus()
	a.setStatus("语法已追加，按 Enter 或点「搜索」")
}

func (a *nativeApp) addCellFilter(field, value, logic string) {
	expr, err := cellFilterExpr(field, value)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	a.appendFilterExpr(expr, logic)
}

func (a *nativeApp) appendFilterExpr(expr, logic string) {
	a.txtSyntax.SetText(joinFilterExpr(a.txtSyntax.Text(), expr, logic))
	a.applySyntax()
}

func joinFilterExpr(current, expr, logic string) string {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	if !strings.HasPrefix(expr, "(") &&
		(strings.Contains(" "+lower+" ", " and ") || strings.Contains(" "+lower+" ", " or ")) {
		expr = "(" + expr + ")"
	}
	current = strings.TrimSpace(current)
	if current == "" {
		return expr
	}
	return current + " " + strings.ToUpper(logic) + " " + expr
}

func (a *nativeApp) resetConditions() {
	tab := 0
	if a.tabs != nil {
		tab = a.tabs.active
	}
	a.txtSyntax.SetText("")
	a.cbLogic.SelectIndex(0)
	a.cbField.SelectIndex(defaultFieldIndex(tab, a.activeFields()))
	a.updateOperators()
	a.txtValue.SetText("")
	a.hotValues = nil
	a.hotCounts = nil
	a.layout()
	a.refreshHotValues()
	if a.tabs != nil {
		switch a.tabs.active {
		case 1:
			a.tabs.procExpr = ""
			a.refreshProcesses()
			a.refreshFixedCount()
		case 2:
			a.tabs.dnsExpr = ""
			a.refreshDNS()
			a.refreshFixedCount()
		default:
			a.reloadTable()
		}
	} else {
		a.reloadTable()
	}
	a.focusSyntax()
}

func (a *nativeApp) reloadTable() {
	expr := strings.TrimSpace(a.txtSyntax.Text())
	if expr == "" {
		a.setStatus("正在载入全部连接…")
	} else {
		a.setStatus("正在检索…")
	}
	a.table.reload(expr, a.table.currentSort(), a.table.currentDesc())
	a.refreshFixedCount()
	if a.tabs != nil {
		a.tabs.refreshAfterFilter()
	}
}

func (a *nativeApp) activeExpr() string {
	if a.tabs != nil {
		switch a.tabs.active {
		case 1:
			return strings.TrimSpace(a.tabs.procExpr)
		case 2:
			return strings.TrimSpace(a.tabs.dnsExpr)
		}
	}
	if a.table != nil {
		return strings.TrimSpace(a.table.currentExpr())
	}
	return ""
}

func (a *nativeApp) autoSetupSysmon() {
	st := sysmonStatus(a.cfg.dataDir)
	if st.Installed && st.ServiceRunning {
		a.applyConfiguredLogSize(st)
		a.enableLive()
		a.syncLiveButton()
		return
	}
	if a.cfg.quiet {
		a.setStatus("未启用 Sysmon 实时采集；可导入 .evtx 分析")
		return
	}
	if st.Error != "" {
		a.message("N-trace",
			"Sysmon 不可用：\n"+st.Error+"\n\n可以继续导入 .evtx 进行离线分析。",
			co.MB_OK|co.MB_ICONINFORMATION)
		a.setStatus("Sysmon 不可用；当前为离线导入模式")
		return
	}
	msg := "当前系统未安装 Sysmon。是否现在安装并开启实时采集？\n\n选择「否」将只使用离线日志导入，仍可正常分析 .evtx。"
	if st.Installed || st.ServiceExists || st.ChannelExists {
		msg = "检测到 Sysmon 安装不完整或服务未运行。是否现在修复安装并开启实时采集？\n\n选择「否」将只使用离线日志导入，仍可正常分析 .evtx。"
	}
	id, err := a.wnd.Hwnd().MessageBox(msg, "N-trace", co.MB_YESNO|co.MB_ICONQUESTION)
	if err != nil || id != co.ID_YES {
		a.setStatus("未启用 Sysmon 实时采集；当前为离线导入模式")
		return
	}
	a.runSysmonTask("安装/修复 Sysmon", func() (string, error) {
		a.stopLive()
		res, err := a.runAdminTask(adminRequest{Task: "install"})
		return res.Output, err
	}, true)
}

func (a *nativeApp) applyConfiguredLogSize(st SysmonStatus) {
	gb := a.cfg.config.SysmonLogMaxGB
	if gb <= 0 {
		return
	}
	want := int64(gb * float64(int64(1)<<30))
	if st.MaxBytes == want {
		return
	}
	go func() {
		err := sysmonSetLogSize(want)
		a.wnd.UiThread(func() {
			if err != nil {
				appPrintf("按配置设置日志上限失败: %v", err)
			} else {
				appPrintf("日志上限已按配置设为 %.1f GB", gb)
			}
		})
	}()
}

// runSysmonTask 在工作线程执行安装类操作，回到 UI 线程刷新状态。
func (a *nativeApp) runSysmonTask(label string, task func() (string, error), startLive bool) {
	a.setBusy(1)
	a.setStatus("正在" + label + "…")
	go func() {
		out, err := task()
		a.wnd.UiThread(func() {
			a.setBusy(-1)
			if err != nil {
				a.setStatus(label + "失败：" + err.Error())
				if out != "" {
					appPrintf("%s", out)
				}
				return
			}
			if startLive {
				a.enableLive()
				a.syncLiveButton()
			}
			a.setStatus(label + "完成")
			a.table.refreshCount()
		})
	}()
}

func (a *nativeApp) enableLive() bool {
	a.liveMu.Lock()
	defer a.liveMu.Unlock()
	if a.live != nil {
		return false
	}
	if err := liveSupported(); err != nil {
		return false
	}
	stop := make(chan struct{})
	cfg := liveConfig{
		Channel: a.cfg.channel, Interval: a.cfg.interval, DataDir: a.cfg.dataDir,
		OnBatch: func(n int, took time.Duration) {
			a.wnd.UiThread(func() { a.onLiveBatch(n, took) })
		},
		IntervalFn: func() time.Duration { return a.refreshEvery },
		Wake:       a.liveWake,
		Stop:       stop,
	}
	a.liveStop = stop
	if cfg.Channel == "" {
		cfg.Channel = defaultChannel
	}
	st := &LiveStats{}
	a.live = st
	go startLive(a.cfg.db, st, cfg, func(f string, args ...interface{}) {
		appPrintf(f, args...)
	})
	return true
}

func (a *nativeApp) toggleLiveReading() {
	enabled, _, _, _ := a.liveInfo()
	if enabled {
		a.stopLive()
		a.setStatus("实时读取已暂停")
		a.syncLiveButton()
		return
	}
	// 清掉失败或已停止的旧采集状态后再重启。
	a.stopLive()
	if !a.enableLive() {
		a.setStatus("无法开始实时读取，请检查 Sysmon 状态或管理员权限")
		a.syncLiveButton()
		return
	}
	a.setStatus("实时读取已开始，正在补读暂停期间的新日志…")
	a.syncLiveButton()
}

func (a *nativeApp) syncLiveButton() {
	if a.btnLive == nil || a.btnLive.Hwnd() == 0 {
		return
	}
	enabled, _, _, _ := a.liveInfo()
	icon := a.icoPlay
	if enabled {
		icon = a.icoPause
		a.btnLive.SetText("暂停读取")
	} else {
		a.btnLive.SetText("开始读取")
	}
	if icon != 0 {
		a.btnLive.Hwnd().SendMessage(co.BM_SETIMAGE,
			win.WPARAM(co.IMAGE_ICON), win.LPARAM(icon))
	}
}

func (a *nativeApp) initLiveButtonIcons() {
	if a.btnLive == nil || a.btnLive.Hwnd() == 0 {
		return
	}
	size := ui.DpiX(16)
	if a.icoPlay == 0 {
		a.icoPlay, _ = makeLiveTransportIcon(false, size)
	}
	if a.icoPause == 0 {
		a.icoPause, _ = makeLiveTransportIcon(true, size)
	}
}

func (a *nativeApp) stopLive() {
	a.liveMu.Lock()
	defer a.liveMu.Unlock()
	if a.live != nil {
		a.live.stop("已停止")
		a.live = nil
	}
	if a.liveStop != nil {
		close(a.liveStop)
		a.liveStop = nil
	}
}

func (a *nativeApp) liveInfo() (enabled, connected bool, total int64, errText string) {
	a.liveMu.Lock()
	defer a.liveMu.Unlock()
	if a.live == nil {
		return false, false, 0, ""
	}
	snap := a.live.snapshot()
	enabled, _ = snap["enabled"].(bool)
	connected, _ = snap["connected"].(bool)
	total, _ = snap["total"].(int64)
	errText, _ = snap["lastError"].(string)
	return enabled, connected, total, errText
}

func (a *nativeApp) onLiveTimer() {
	a.liveMu.Lock()
	st := a.live
	a.liveMu.Unlock()
	if st == nil {
		return
	}
	snap := st.snapshot()
	enabled, _ := snap["enabled"].(bool)
	connected, _ := snap["connected"].(bool)
	total, _ := snap["total"].(int64)
	lastErr, _ := snap["lastError"].(string)
	mode, _ := snap["mode"].(string)
	reading, _ := snap["reading"].(bool)
	lastBatch, _ := snap["lastBatch"].(int)
	lastRead, _ := snap["lastRead"].(int64)
	lastTook, _ := snap["lastTook"].(int64)

	if enabled != a.liveWasOn {
		a.liveWasOn = enabled
		a.syncLiveButton()
	}
	if a.busy == 0 {
		switch {
		case !enabled:
			a.setStatus("实时采集已停止" + suffixErr(lastErr))
		case mode == "backfill":
			a.setStatus(fmt.Sprintf("正在补读历史日志 · 已读取 %s 条", commaInt64(total)))
		case connected:
			a.liveDots++
			recentRead := lastRead > 0 && time.Since(time.UnixMilli(lastRead)) < 900*time.Millisecond
			if reading || recentRead {
				a.setStatus("正在读取日志" + strings.Repeat(".", 1+a.liveDots%3))
			} else {
				a.setStatus(liveReadText(lastBatch, lastTook))
			}
		case lastErr != "":
			if liveNeedsAdmin(lastErr) {
				a.setStatus("实时采集不可用：需要管理员权限或加入 Event Log Readers 组")
			} else {
				a.setStatus("实时采集：" + lastErr)
			}
		default:
			a.setStatus("实时采集正在连接…")
		}
	}
	a.lastLiveTotal = total
}

// onLiveBatch 在每批事件入库成功后立即刷新界面，避免实时条数和表格总数不一致。
func (a *nativeApp) onLiveBatch(n int, took time.Duration) {
	if a.table == nil {
		return
	}
	a.setStatus(liveReadText(n, took.Milliseconds()))
	a.refreshFixedCount()
	a.refreshHotValuesOnData()
	if a.tabs != nil && (a.tabs.active == 1 || a.tabs.active == 2) {
		a.tabs.refreshActive()
		return
	}
	a.table.onLiveChange()
}

func liveReadText(n int, tookMS int64) string {
	return fmt.Sprintf("读取 %d 条日志，耗时 %.1f 秒", n, float64(tookMS)/1000)
}

func suffixErr(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "：" + s
}

func liveNeedsAdmin(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(s, "拒绝访问") || strings.Contains(l, "access is denied") ||
		strings.Contains(l, "administrator") || strings.Contains(l, "admin")
}

func (a *nativeApp) message(title, text string, flags co.MB) {
	a.wnd.Hwnd().MessageBox(text, title, flags)
}

func (a *nativeApp) restartElevated() {
	if isAdmin() {
		a.message("N-trace", "当前已经是管理员权限。", co.MB_OK|co.MB_ICONINFORMATION)
		return
	}
	id, err := a.wnd.Hwnd().MessageBox(
		"将以管理员身份重启程序，用于读取 Sysmon 实时日志。是否继续？",
		"N-trace", co.MB_YESNO|co.MB_ICONQUESTION)
	if err != nil || id != co.ID_YES {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		a.message("N-trace", "获取程序路径失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	params := fmt.Sprintf("-data %s -q", quoteWinArg(a.cfg.dataDir))
	if err := startElevatedProcess(a.wnd.Hwnd(), exe, params, a.cfg.dataDir); err != nil {
		if err == errAdminCancelled {
			a.setStatus("已取消管理员授权")
			return
		}
		a.message("N-trace", "以管理员身份重启失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	appPrintf("已请求管理员模式重启")
	a.stopLive()
	a.wnd.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
}

func formatBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

func commaInt(n int) string { return commaInt64(int64(n)) }

func commaInt64(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func displayBase(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	if p == "" {
		return "System"
	}
	return p
}

func timeText(ms int64, loc *time.Location) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).In(loc).Format("2006-01-02 15:04:05")
}
