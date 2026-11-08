//go:build windows

package main

import (
	"strconv"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
)

const menuSettings = 40005

// openSettingsPanel 数据保留与原始事件存储设置。
func (a *nativeApp) openSettingsPanel() {
	modal := ui.NewModal(a.wnd, ui.OptsModal().
		Title("数据与保留设置").
		Size(ui.Dpi(500, 250)).
		Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_VISIBLE))

	ui.NewStatic(modal, ui.OptsStatic().
		Text("数据保留天数（0 表示不自动清理）").
		Position(ui.Dpi(20, 20)).
		Size(ui.Dpi(440, 20)))
	edDays := ui.NewEdit(modal, ui.OptsEdit().
		Text(strconv.Itoa(a.cfg.config.DataRetentionDays)).
		Position(ui.Dpi(20, 44)).
		Width(ui.DpiX(120)))
	ui.NewStatic(modal, ui.OptsStatic().
		Text("超过保留期的连接、DNS、进程数据会每 6 小时自动分批清理，并回收磁盘空间。").
		Position(ui.Dpi(20, 74)).
		Size(ui.Dpi(450, 20)))
	chkRaw := ui.NewCheckBox(modal, ui.OptsCheckBox().
		Text("保存原始事件 JSON（关闭可减少约一半磁盘占用，详情页不再显示原始事件）").
		Position(ui.Dpi(20, 104)).
		Size(ui.Dpi(460, 24)).
		State(func() co.BST {
			if a.cfg.config.StoreRaw {
				return co.BST_CHECKED
			}
			return co.BST_UNCHECKED
		}()))
	ui.NewStatic(modal, ui.OptsStatic().
		Text("注意：raw 开关只影响之后写入的数据；修改保留天数后点击“立即清理”可马上生效。").
		Position(ui.Dpi(20, 134)).
		Size(ui.Dpi(460, 20)))

	btnClean := ui.NewButton(modal, ui.OptsButton().
		Text("立即清理").
		Position(ui.Dpi(20, 176)).
		Width(ui.DpiX(88)))
	btnSave := ui.NewButton(modal, ui.OptsButton().
		Text("保存").
		Position(ui.Dpi(302, 176)).
		Width(ui.DpiX(84)))
	btnClose := ui.NewButton(modal, ui.OptsButton().
		Text("关闭").
		Position(ui.Dpi(396, 176)).
		Width(ui.DpiX(84)))

	btnClean.On().BnClicked(func() {
		days, ok := parseRetentionDays(edDays.Text())
		if !ok {
			a.message("数据与保留设置", "保留天数必须是 0~3650 的整数", co.MB_OK|co.MB_ICONWARNING)
			return
		}
		if days == 0 {
			a.message("数据与保留设置", "当前设置为不自动清理（0 天）", co.MB_OK|co.MB_ICONINFORMATION)
			return
		}
		btnClean.Hwnd().EnableWindow(false)
		a.setStatus("正在清理过期数据…")
		db := a.cfg.db
		go func() {
			_, err := db.CleanupRetention(days, appPrintf)
			a.wnd.UiThread(func() {
				btnClean.Hwnd().EnableWindow(true)
				if err != nil {
					a.setStatus("清理失败：" + err.Error())
					a.message("数据与保留设置", "清理失败：\n"+err.Error(), co.MB_OK|co.MB_ICONERROR)
					return
				}
				a.setStatus("过期数据清理完成")
			})
		}()
	})
	btnSave.On().BnClicked(func() {
		days, ok := parseRetentionDays(edDays.Text())
		if !ok {
			a.message("数据与保留设置", "保留天数必须是 0~3650 的整数", co.MB_OK|co.MB_ICONWARNING)
			return
		}
		cfg := loadAppConfig(a.cfg.dataDir)
		cfg.DataRetentionDays = days
		cfg.StoreRaw = chkRaw.IsChecked()
		_ = cfg.save(a.cfg.dataDir)
		a.cfg.config = cfg
		a.cfg.db.SetStoreRaw(cfg.StoreRaw)
		appPrintf("配置已更新：数据保留 %d 天，原始事件 %v", cfg.DataRetentionDays, cfg.StoreRaw)
		a.setStatus("数据与保留设置已保存")
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	btnClose.On().BnClicked(func() {
		modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
	})
	modal.On().WmKeyDown(func(p ui.WmKey) {
		if p.VirtualKeyCode() == co.VK_ESCAPE && !p.IsReleasingKey() {
			modal.Hwnd().PostMessage(co.WM_CLOSE, 0, 0)
		}
	})
	modal.ShowModal()
}

func parseRetentionDays(text string) (int, bool) {
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || n > 3650 {
		return 0, false
	}
	return n, true
}
