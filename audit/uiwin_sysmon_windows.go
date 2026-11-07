//go:build windows

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

type sysmonPanel struct {
	app        *nativeApp
	modal      *ui.Modal
	edStatus   *ui.Edit
	srcList    *ui.ListView
	srcNames   []string
	edGB       *ui.Edit
	chkDNS     *ui.CheckBox
	edArgs     *ui.Edit
	edOutput   *ui.Edit
	btnLog     *ui.Button
	btnUninst  *ui.Button
	btnArgs    *ui.Button
	btnElevate *ui.Button
	hTheme     win.HTHEME
	working    bool
}

func (a *nativeApp) openSysmonPanel() {
	p := &sysmonPanel{app: a}
	p.build()
	p.loadStatus()
	p.modal.ShowModal()
}

func (p *sysmonPanel) build() {
	p.modal = ui.NewModal(p.app.wnd, ui.OptsModal().
		Title("日志源管理").
		Size(ui.Dpi(900, 760)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	ui.NewStatic(p.modal, ui.OptsStatic().
		Text("本地导入日志").
		Position(ui.Dpi(12, 10)).
		Size(ui.Dpi(120, 20)))
	p.srcList = ui.NewListView(p.modal, ui.OptsListView().
		Position(ui.Dpi(12, 32)).
		Size(ui.Dpi(868, 120)).
		CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS|co.LVS_SINGLESEL).
		CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_DOUBLEBUFFER).
		Column("文件", ui.DpiX(320)).
		Column("大小", ui.DpiX(90)).
		Column("事件数", ui.DpiX(90)).
		Column("导入时间", ui.DpiX(160)).
		Column("操作", ui.DpiX(70)))

	ui.NewStatic(p.modal, ui.OptsStatic().
		Text("Sysmon 实时采集").
		Position(ui.Dpi(12, 160)).
		Size(ui.Dpi(160, 20)))
	p.edStatus = ui.NewEdit(p.modal, ui.OptsEdit().
		Position(ui.Dpi(12, 182)).
		Width(ui.DpiX(868)).
		Height(ui.DpiY(216)).
		CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL))

	ui.NewStatic(p.modal, ui.OptsStatic().
		Text("日志上限 (GB)").
		Position(ui.Dpi(12, 406)).
		Size(ui.Dpi(100, 20)))
	p.edGB = ui.NewEdit(p.modal, ui.OptsEdit().
		Position(ui.Dpi(116, 402)).
		Width(ui.DpiX(64)))
	p.btnLog = ui.NewButton(p.modal, ui.OptsButton().
		Text("应用").
		Position(ui.Dpi(188, 400)).
		Width(ui.DpiX(78)))
	p.chkDNS = ui.NewCheckBox(p.modal, ui.OptsCheckBox().
		Text("启用 DNS 查询记录（EID 22）").
		Position(ui.Dpi(300, 404)).
		Size(ui.Dpi(300, 22)))

	ui.NewStatic(p.modal, ui.OptsStatic().
		Text("安装参数（保存后自动重新安装）").
		Position(ui.Dpi(12, 436)).
		Size(ui.Dpi(420, 20)))
	p.edArgs = ui.NewEdit(p.modal, ui.OptsEdit().
		Position(ui.Dpi(12, 458)).
		Width(ui.DpiX(868)).
		Height(ui.DpiY(54)).
		CtrlStyle(co.ES_MULTILINE|co.ES_AUTOVSCROLL).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL))

	p.btnArgs = ui.NewButton(p.modal, ui.OptsButton().
		Text("保存参数重新安装").
		Position(ui.Dpi(12, 522)).
		Width(ui.DpiX(150)))
	p.btnUninst = ui.NewButton(p.modal, ui.OptsButton().
		Text("卸载").
		Position(ui.Dpi(170, 522)).
		Width(ui.DpiX(88)))
	p.btnElevate = ui.NewButton(p.modal, ui.OptsButton().
		Text("以管理员身份重启").
		Position(ui.Dpi(266, 522)).
		Width(ui.DpiX(160)))
	if isAdmin() {
		p.btnElevate.Hwnd().EnableWindow(false)
	}

	ui.NewStatic(p.modal, ui.OptsStatic().
		Text("执行输出").
		Position(ui.Dpi(12, 558)).
		Size(ui.Dpi(120, 20)))
	p.edOutput = ui.NewEdit(p.modal, ui.OptsEdit().
		Position(ui.Dpi(12, 580)).
		Width(ui.DpiX(868)).
		Height(ui.DpiY(160)).
		CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL|co.ES_AUTOHSCROLL).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL|co.WS_HSCROLL))

	p.btnLog.On().BnClicked(func() { p.applyLogSize() })
	p.btnUninst.On().BnClicked(func() { p.uninstall() })
	p.btnArgs.On().BnClicked(func() { p.saveArgs() })
	p.btnElevate.On().BnClicked(func() { p.app.restartElevated() })
	p.srcList.On().NmClick(func(p2 *win.NMITEMACTIVATE) {
		if p2.ISubItem == 4 && p2.IItem >= 0 {
			p.deleteSourceAt(int(p2.IItem))
		}
	})
	p.srcList.On().LvnKeyDown(func(p2 *win.NMLVKEYDOWN) {
		if p2.WVKey == co.VK_DELETE {
			p.deleteSelectedSource()
		}
	})
	p.srcList.On().NmCustomDraw(p.onSourceCustomDraw)
	p.modal.On().WmCreate(func(_ ui.WmCreate) int {
		p.hTheme, _ = p.srcList.Hwnd().OpenThemeData("BUTTON")
		return 0
	})
	p.modal.On().WmDestroy(func() {
		if p.hTheme != 0 {
			p.hTheme.CloseThemeData()
			p.hTheme = 0
		}
	})
}

func (p *sysmonPanel) onSourceCustomDraw(cd *win.NMLVCUSTOMDRAW) co.CDRF {
	if cd.Nmcd.DwDrawStage == co.CDDS_PREPAINT {
		return co.CDRF_NOTIFYSUBITEMDRAW
	}
	if cd.Nmcd.DwDrawStage&co.CDDS_ITEMPREPAINT != co.CDDS_ITEMPREPAINT ||
		cd.Nmcd.DwDrawStage&co.CDDS_SUBITEM == 0 || cd.ISubItem != 4 {
		return co.CDRF_DODEFAULT
	}
	rc := win.RECT{Left: 4}
	if ret, _ := p.srcList.Hwnd().SendMessage(co.LVM_GETSUBITEMRECT,
		win.WPARAM(cd.Nmcd.DwItemSpec), win.LPARAM(unsafe.Pointer(&rc))); ret == 0 {
		return co.CDRF_DODEFAULT
	}
	rc.Left += int32(ui.DpiX(6))
	rc.Right -= int32(ui.DpiX(6))
	rc.Top += int32(ui.DpiY(2))
	rc.Bottom -= int32(ui.DpiY(2))
	if p.hTheme != 0 {
		_ = p.hTheme.DrawThemeBackground(cd.Nmcd.Hdc, co.VS(0x00010001), &rc, nil)
	} else {
		_ = cd.Nmcd.Hdc.Rectangle(rc)
	}
	_, _ = cd.Nmcd.Hdc.SetBkMode(co.BKMODE_TRANSPARENT)
	_, _ = cd.Nmcd.Hdc.SetTextColor(0)
	_, _ = cd.Nmcd.Hdc.DrawText("删除", &rc, co.DT_CENTER|co.DT_VCENTER|co.DT_SINGLELINE)
	return co.CDRF_SKIPDEFAULT
}

func (p *sysmonPanel) loadStatus() {
	if p.working {
		return
	}
	p.setWorking(true)
	p.edStatus.SetText("正在读取日志源状态…")
	go func() {
		st := sysmonStatus(p.app.cfg.dataDir)
		meta, _ := p.app.cfg.db.Meta()
		srcs, _ := meta["sources"].([]map[string]interface{})
		enabled, connected, total, liveErr := p.app.liveInfo()
		p.modal.UiThread(func() {
			p.applyStatus(st, srcs, enabled, connected, total, liveErr)
			p.setWorking(false)
		})
	}()
}

func (p *sysmonPanel) applyStatus(st SysmonStatus, srcs []map[string]interface{}, liveEnabled, liveConnected bool, liveTotal int64, liveErr string) {
	state := "未安装"
	switch {
	case st.Installed:
		if st.ServiceRunning {
			state = "已安装（运行中）"
		} else {
			state = "已安装（服务未运行）"
		}
	case st.ServiceExists:
		state = "服务存在，日志通道缺失"
	case st.ChannelExists:
		state = "日志通道存在，服务缺失"
	}
	logSize := formatBytes(st.LogBytes)
	maxSize := formatBytes(st.MaxBytes)
	if st.MaxBytes == 0 {
		maxSize = "未设置"
	}
	admin := "普通用户（安装/卸载需要管理员权限）"
	if st.Admin {
		admin = "管理员"
	}
	dns := "不支持"
	if st.DNSSupported {
		dns = "支持（未启用）"
		if st.DNSEnabled {
			dns = "支持（已启用）"
		}
	}
	p.fillSources(srcs)
	lines := []string{"【Sysmon 实时采集】"}
	liveState := "未开启"
	switch {
	case liveConnected:
		liveState = fmt.Sprintf("已连接 · 已入库 %s 条", commaInt64(liveTotal))
	case liveEnabled && liveErr != "":
		liveState = liveErr
	case liveEnabled:
		liveState = "未连接"
	}
	lines = append(lines,
		"实时采集："+liveState,
		"状态："+state,
		"系统："+st.OSVersion+"（"+st.Arch+"）",
		"安装包："+st.Package+" / "+st.PackageFile,
		"服务："+valueOr(st.ServiceName, "无"),
		"日志："+valueOr(st.LogPath, "未找到"),
		"大小："+logSize+" / 上限 "+maxSize,
		"权限："+admin,
		"DNS："+dns)
	if st.Error != "" {
		lines = append(lines, "错误："+st.Error)
	}
	p.edStatus.SetText(strings.Join(lines, "\r\n"))
	if st.MaxBytes > 0 {
		p.edGB.SetText(strconv.FormatFloat(float64(st.MaxBytes)/float64(int64(1)<<30), 'f', 1, 64))
	}
	p.chkDNS.SetCheck(st.DNSEnabled)
	p.edArgs.SetText(st.EffectiveArgs)
}

func (p *sysmonPanel) setWorking(v bool) {
	p.working = v
	enabled := !v
	p.btnUninst.Hwnd().EnableWindow(enabled)
	p.btnArgs.Hwnd().EnableWindow(enabled)
	p.btnLog.Hwnd().EnableWindow(enabled)
	p.chkDNS.Hwnd().EnableWindow(enabled)
	p.srcList.Hwnd().EnableWindow(enabled)
}

func (p *sysmonPanel) uninstall() {
	id, err := p.modal.Hwnd().MessageBox(
		"卸载 Sysmon 会停止实时采集并删除服务。是否继续？",
		"卸载 Sysmon", co.MB_YESNO|co.MB_ICONQUESTION)
	if err != nil || id != co.ID_YES {
		return
	}
	p.runTask("卸载 Sysmon", func() (string, error) {
		p.app.stopLive()
		res, err := p.app.runAdminTask(adminRequest{Task: "uninstall"})
		return res.Output, err
	}, false)
}

func (p *sysmonPanel) saveArgs() {
	text := p.edArgs.Text()
	dns := p.chkDNS.IsChecked()
	p.runTask("保存参数并重新安装", func() (string, error) {
		p.app.stopLive()
		res, err := p.app.runAdminTask(adminRequest{Task: "install", Args: &text, DNSSet: true, DNS: dns})
		return res.Output, err
	}, true)
}

func (p *sysmonPanel) applyLogSize() {
	if p.working {
		return
	}
	gb, err := strconv.ParseFloat(strings.TrimSpace(p.edGB.Text()), 64)
	if err != nil || gb <= 0 {
		p.edOutput.SetText("日志上限无效，请输入大于 0 的 GB 数。")
		return
	}
	p.setWorking(true)
	p.edOutput.SetText("正在调整日志上限…")
	go func() {
		res, err := p.app.runAdminTask(adminRequest{Task: "logsize", LogGB: gb})
		p.modal.UiThread(func() {
			p.setWorking(false)
			if err != nil {
				if errors.Is(err, errAdminCancelled) {
					p.edOutput.SetText("已取消管理员授权。")
					return
				}
				p.edOutput.SetText("调整日志上限失败：" + err.Error())
				return
			}
			p.edOutput.SetText(res.Output)
			p.app.cfg.config.SysmonLogMaxGB = gb
			_ = p.app.cfg.config.save(p.app.cfg.dataDir)
			p.loadStatus()
		})
	}()
}

func (p *sysmonPanel) runTask(label string, task func() (string, error), startLive bool) {
	if p.working {
		return
	}
	p.setWorking(true)
	p.edOutput.SetText("正在" + label + "…")
	appPrintf("开始%s", label)
	go func() {
		out, err := task()
		p.modal.UiThread(func() {
			p.setWorking(false)
			if err != nil {
				p.edOutput.SetText(label + "失败：" + err.Error() + "\r\n" + out)
				appPrintf("%s失败：%v\n%s", label, err, out)
				if !errors.Is(err, errAdminCancelled) {
					p.modal.Hwnd().MessageBox(label+"失败：\n"+err.Error(), "Sysmon", co.MB_OK|co.MB_ICONERROR)
				}
				return
			}
			if out == "" {
				out = label + "完成。"
			}
			p.edOutput.SetText(toCRLF(out))
			appPrintf("%s完成\n%s", label, out)
			if startLive {
				p.app.enableLive()
			}
			p.loadStatus()
		})
	}()
}

func valueOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func (p *sysmonPanel) fillSources(srcs []map[string]interface{}) {
	withListRedraw(p.srcList, func() {
		p.srcList.DeleteAllItems()
		p.srcNames = nil
		for _, s := range srcs {
			name, _ := s["name"].(string)
			if name == "" || name == liveSource {
				continue
			}
			size, _ := s["bytes"].(int64)
			events, _ := s["events"].(int64)
			at, _ := s["at"].(int64)
			atText := ""
			if at > 0 {
				atText = time.Unix(at, 0).Format("2006-01-02 15:04")
			}
			p.srcList.AddItem(name, formatBytes(size), commaInt64(events), atText, "删除")
			p.srcNames = append(p.srcNames, name)
		}
	})
}

func (p *sysmonPanel) deleteSelectedSource() {
	sel := p.srcList.SelectedItems()
	if len(sel) == 0 {
		p.edOutput.SetText("请先在列表中选择要删除的导入日志。")
		return
	}
	p.deleteSourceAt(sel[0].Index())
}

func (p *sysmonPanel) deleteSourceAt(idx int) {
	if idx < 0 || idx >= len(p.srcNames) || p.working {
		return
	}
	name := p.srcNames[idx]
	id, err := p.modal.Hwnd().MessageBox(
		"删除导入日志「"+name+"」会同时删除它导入的连接和 DNS 记录，是否继续？",
		"删除导入日志", co.MB_YESNO|co.MB_ICONWARNING)
	if err != nil || id != co.ID_YES {
		return
	}
	p.setWorking(true)
	p.edOutput.SetText("正在删除 " + name + " …")
	go func() {
		nConn, nDNS, err := p.app.cfg.db.DeleteSource(name)
		p.modal.UiThread(func() {
			p.setWorking(false)
			if err != nil {
				p.edOutput.SetText("删除失败：" + err.Error())
				return
			}
			p.edOutput.SetText(fmt.Sprintf("已删除 %s：连接 %s 条，DNS %s 条",
				name, commaInt64(nConn), commaInt64(nDNS)))
			p.loadStatus()
			p.app.reloadTable()
		})
	}()
}
