//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/x/cosh"
	"github.com/rodrigocfd/windigo/x/winsh"
)

func (a *nativeApp) importDialog() {
	paths, err := openEvtxDialog(a.wnd.Hwnd())
	if err != nil {
		a.message("导入日志", err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	if len(paths) > 0 {
		a.importPaths(paths)
	}
}

func (a *nativeApp) importPaths(paths []string) {
	if len(paths) == 0 {
		return
	}
	if a.importing {
		a.setStatus("已有导入任务正在进行")
		return
	}
	a.importing = true
	a.setBusy(1)
	a.setStatus(fmt.Sprintf("正在导入 %d 个路径…", len(paths)))
	appPrintf("开始导入 %d 个路径：%v", len(paths), paths)
	start := time.Now()

	go func() {
		stats, err := a.cfg.db.Import(paths)
		a.wnd.UiThread(func() {
			a.importing = false
			a.setBusy(-1)
			if err != nil {
				a.setStatus("导入失败：" + err.Error())
				appPrintf("导入失败：%v", err)
				a.message("导入日志", "导入失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
				return
			}
			msg := fmt.Sprintf("导入完成：%d 个文件 · %s 条连接 · %s 条 DNS · 耗时 %s",
				len(stats.Files), commaInt(stats.Conns), commaInt(stats.DNS), time.Since(start).Round(time.Millisecond))
			a.setStatus(msg)
			appPrintf("%s", msg)
			a.reloadTable()
		})
	}()
}

func (a *nativeApp) exportDialog() {
	if a.exporting {
		a.setStatus("已有导出任务正在进行")
		return
	}
	tab := 0
	if a.tabs != nil {
		tab = a.tabs.active
	}
	tabNames := []string{"connections", "processes", "dns"}
	tabLabels := []string{"连接", "进程", "DNS"}
	if tab < 0 || tab >= len(tabNames) {
		tab = 0
	}
	name := fmt.Sprintf("n-trace-%s-%s.csv", tabNames[tab], time.Now().Format("20060102-150405"))
	path, err := openSaveDialog(a.wnd.Hwnd(), name)
	if err != nil {
		a.message("导出 CSV", err.Error(), co.MB_OK|co.MB_ICONERROR)
		return
	}
	if path == "" {
		return
	}
	if filepath.Ext(path) == "" {
		path += ".csv"
	}

	a.exporting = true
	a.setBusy(1)
	a.btnExport.Hwnd().EnableWindow(false)
	a.setStatus("正在导出…")
	expr := a.activeExpr()
	start := time.Now()
	appPrintf("开始导出 %s CSV：%s（条件：%q）", tabLabels[tab], path, expr)

	go func() {
		f, err := os.Create(path)
		if err != nil {
			a.exportDone(err, path, 0, start, tabLabels[tab])
			return
		}
		buf := bufio.NewWriterSize(f, 256<<10)
		progress := func(n int) {
			a.wnd.UiThread(func() {
				a.setStatus("正在导出 " + commaInt(n) + " 条…")
			})
		}
		var n int
		switch tab {
		case 1:
			n, err = exportProcessCSV(a.cfg.db, buf, expr, a.loc, progress)
		case 2:
			n, err = exportDNSCSV(a.cfg.db, buf, expr, a.loc, progress)
		default:
			n, err = exportCSV(a.cfg.db, buf, expr, a.loc, progress)
		}
		if ferr := buf.Flush(); err == nil {
			err = ferr
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
		}
		a.exportDone(err, path, n, start, tabLabels[tab])
	}()
}

func (a *nativeApp) exportDone(err error, path string, n int, start time.Time, label string) {
	a.wnd.UiThread(func() {
		a.exporting = false
		a.setBusy(-1)
		a.btnExport.Hwnd().EnableWindow(true)
		if err != nil {
			a.setStatus("导出失败：" + err.Error())
			appPrintf("导出失败：%v", err)
			a.message("导出 CSV", "导出失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
			return
		}
		msg := fmt.Sprintf("已导出 %s 条%s日志，耗时 %.1f 秒",
			commaInt(n), label, time.Since(start).Seconds())
		a.setStatus("就绪")
		appPrintf("%s -> %s", msg, path)
		a.showExportSuccess(msg, path)
	})
}

func (a *nativeApp) showExportSuccess(msg, path string) {
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("导出 CSV").
		Size(ui.Dpi(560, 238)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	ui.NewStatic(modal, ui.OptsStatic().
		Text("导出成功").
		Position(ui.Dpi(20, 24)).
		Size(ui.Dpi(520, 28)).
		CtrlStyle(co.SS_CENTER|co.SS_CENTERIMAGE))
	ui.NewEdit(modal, ui.OptsEdit().
		Text(msg+"\r\n\r\n文件位置："+path).
		Position(ui.Dpi(32, 60)).
		Width(ui.DpiX(496)).
		Height(ui.DpiY(94)).
		CtrlStyle(co.ES_MULTILINE|co.ES_READONLY).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE).
		WndExStyle(0))

	btnOpen := ui.NewButton(modal, ui.OptsButton().
		Text("打开所在目录").
		Position(ui.Dpi(160, 174)).
		Width(ui.DpiX(120)))
	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(310, 174)).
		Width(ui.DpiX(90)))
	btnOpen.On().BnClicked(func() {
		_ = exec.Command("explorer.exe", "/select,", path).Start()
	})
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	brush, _ := win.GetSysColorBrush(co.COLOR_BTNFACE)
	modal.On().WmCtlColorEdit(func(p ui.WmCtlColor) win.HBRUSH {
		_, _ = p.Hdc().SetBkColor(win.GetSysColor(co.COLOR_BTNFACE))
		return brush
	})
	modal.ShowModal()
}

func openEvtxDialog(parent win.HWND) ([]string, error) {
	rel := win.NewOleReleaser()
	defer rel.Release()

	var fod *winsh.IFileOpenDialog
	if err := win.CoCreateInstance(rel, &cosh.CLSID_FileOpenDialog, nil, co.CLSCTX_INPROC_SERVER, &fod); err != nil {
		return nil, err
	}
	opts, _ := fod.GetOptions()
	_ = fod.SetOptions(opts |
		cosh.FOS_FORCEFILESYSTEM |
		cosh.FOS_FILEMUSTEXIST |
		cosh.FOS_PATHMUSTEXIST |
		cosh.FOS_ALLOWMULTISELECT)
	_ = fod.SetTitle("选择 Sysmon 事件日志")
	_ = fod.SetFileTypes([]winsh.COMDLG_FILTERSPEC{
		{Name: "事件日志 (*.evtx)", Spec: "*.evtx"},
		{Name: "所有文件", Spec: "*.*"},
	})
	_ = fod.SetFileTypeIndex(1)

	ok, err := fod.Show(parent)
	if isDialogCanceled(err) {
		return nil, nil
	}
	if err != nil || !ok {
		return nil, err
	}
	items, err := fod.GetResults(rel)
	if err != nil {
		if isDialogCanceled(err) {
			return nil, nil
		}
		return nil, err
	}
	return items.EnumDisplayNames(cosh.SIGDN_FILESYSPATH)
}

func openSaveDialog(parent win.HWND, defaultName string) (string, error) {
	rel := win.NewOleReleaser()
	defer rel.Release()

	var fsd *winsh.IFileSaveDialog
	if err := win.CoCreateInstance(rel, &cosh.CLSID_FileSaveDialog, nil, co.CLSCTX_INPROC_SERVER, &fsd); err != nil {
		return "", err
	}
	opts, _ := fsd.GetOptions()
	_ = fsd.SetOptions(opts |
		cosh.FOS_FORCEFILESYSTEM |
		cosh.FOS_PATHMUSTEXIST |
		cosh.FOS_OVERWRITEPROMPT)
	_ = fsd.SetTitle("导出筛选结果")
	_ = fsd.SetDefaultExtension("csv")
	_ = fsd.SetFileName(defaultName)
	_ = fsd.SetFileTypes([]winsh.COMDLG_FILTERSPEC{
		{Name: "CSV 文件 (*.csv)", Spec: "*.csv"},
		{Name: "所有文件", Spec: "*.*"},
	})
	_ = fsd.SetFileTypeIndex(1)

	ok, err := fsd.Show(parent)
	if isDialogCanceled(err) {
		return "", nil
	}
	if err != nil || !ok {
		return "", err
	}
	item, err := fsd.GetResult(rel)
	if err != nil {
		if isDialogCanceled(err) {
			return "", nil
		}
		return "", err
	}
	return item.GetDisplayName(cosh.SIGDN_FILESYSPATH)
}

func isDialogCanceled(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "0x800704c7") ||
		strings.Contains(s, "operation was canceled") ||
		strings.Contains(s, "operation was cancelled") ||
		strings.Contains(s, "操作已被取消") ||
		strings.Contains(s, "已取消")
}
