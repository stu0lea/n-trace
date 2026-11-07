# Trace-Audit 原生 UI 方案（dev-2.0）

目标：Win7 – Win11 单 exe，原生窗口，不依赖浏览器 / WebView2 / .NET / 运行时。
本文是技术选型与落地设计，确认后再开始编码。

## 1. 结论

| 项 | 决定 |
| --- | --- |
| GUI 库 | `github.com/rodrigocfd/windigo` v0.2.7（纯 Go 直调 Win32，无 CGo） |
| 表格 | `SysListView32` 虚拟列表：`LVS_OWNERDATA` + `LVN_GETDISPINFO` |
| 编译 | Go 1.20（最后一个支持 Win7 的版本），`windows/amd64` + `windows/arm64` |
| 主题 | 仅系统原生浅色（按最新要求，不做暗色） |
| 后端 | `db.go` / `parse.go` / `live*.go` / `sysmon*.go` / `geo.go` 全部复用，不改逻辑 |
| 浏览器版 | 保留 `web.go`，非 Windows 平台和 `-web` 调试参数仍走它 |

## 2. 候选对比（为什么是 windigo）

| 方案 | 结论 |
| --- | --- |
| WebView2 / 任何 WebView | Win7 装不了 WebView2，直接排除 |
| `lxn/walk` | 已归档停更，且没有 owner-data 虚拟列表封装 |
| Fyne / Gio | 需要 OpenGL，应急场景常见 RDP、虚拟机无 GPU 会花屏/起不来；体积 ≥ 40MB，中文要内嵌几 MB 字体 |
| WPF / WinForms | 要 .NET 运行时，破坏「单 exe 零依赖」 |
| 自写 Win32 封装 | 等于重造 windigo（700+ 函数），工期翻几倍 |
| **windigo** | 声明支持 Go 1.20 / Win7；原生控件外观；单 exe 增量约 1MB |

## 3. 已验证（本轮实测，非推测）

- windigo `go.mod` 声明 `go 1.20`，README 明确「based in Go 1.20, can be built in Windows 7 and above」
- 源码确认可用：`co.LVS_OWNERDATA`、`co.LVM_SETITEMCOUNT`、`co.LVM_REDRAWITEMS`、`ui.ListViewEvents.LvnGetDispInfo`、`ui.ListViewEvents.NmCustomDraw`
- 配套能力齐备：`x/winsh.IFileOpenDialog`（Vista+ 系统文件框）、`WM_DROPFILES` + `win.HDROP`（拖放）、`ui.HeaderEvents.HdnItemClick`（点表头排序）、`ui.StatusBar`
- POC（见 `docs/native-ui-poc/`）：主窗口 + 2 个下拉 + 输入框 + 4 个按钮 + 12 列 50 万行虚拟表 + 状态栏 + 跨线程重绘，用 `go1.20.14` 交叉编译 **amd64 / arm64 均通过**，exe 约 1.5MB
- 资源文件：`go-winres` 在 macOS 上生成 `rsrc_windows_amd64.syso` / `rsrc_windows_arm64.syso`，内置清单含 comctl32 v6 + dpiAware + Vista~Win11 supportedOS，两个架构链接均正常（原生主题、Win7 上不会退化成 Win95 外观）

## 4. 代码结构

全部留在 `package audit`，用文件名后缀隔离平台，避免为导出内部函数做无谓重构：

```
audit/
  main.go                    入口：参数解析、打开 DB、选择 UI
  ui_native_windows.go       nativeRun()：启动原生界面（windows）
  ui_web_other.go            nativeRun()：启动浏览器界面（darwin/linux）、-web 强制
  uiwin_app_windows.go       主窗口、控件组装、事件绑定
  uiwin_table_windows.go     虚拟列表 + 块缓存 + 排序 + 选中/详情
  uiwin_query_windows.go     条件列表 -> 表达式；worker 调度与回主线程
  uiwin_detail_windows.go    详情窗口（字段表 + raw JSON）
  uiwin_sysmon_windows.go    Sysmon 安装/卸载/日志上限/DNS/参数
  uiwin_dialog_windows.go    IFileOpenDialog + 拖放
  rsrc_windows_amd64.syso    资源（清单 + 图标，go-winres 生成）
  rsrc_windows_arm64.syso
```

`web.go`、`audit/ui/index.html` 保留不动。

## 5. 表格数据流（几十万行不卡的关键）

1. 条件变化 → 拼成表达式 → 工作线程调现有 `db.Query(expr, 0, 0, sort, desc)` 只取 `total`
2. 行数据按 **512 行 / 块** 分页取（`Query(expr, 512, block*512, sort, desc)`），LRU 常驻 16 块 ≈ 8192 行，内存可控
3. `LVN_GETDISPINFO` 只读内存缓存；未命中就写 `…`，后台加载该块，完成后 `PostMessage(WM_APP_REDRAW)` 重绘可见区
4. 排序交给 SQL（`ORDER BY` 与分页同一条语句），不做内存排序；点表头只改 `sortField/desc` 再重新分页
5. 实时采集有新数据时：更新 total；若列表停在顶部且无筛选则重建首块，用户已滚动则只更新计数，避免视图跳动

## 6. 线程模型

- UI 线程 `runtime.LockOSThread()`，只碰控件
- 所有 SQLite / `wevtutil` / Sysmon 安装调用跑在工作 goroutine
- 工作线程回 UI 统一用 `PostMessage(co.WM_APP+n)`，不做跨线程直接操作控件

## 7. 界面布局

- 顶部数据源行：文件名、完整路径、大小（导入模式=选中文件；实时模式=系统 Sysmon 日志）
- 检索行：`AND/OR 下拉（默认 AND）` → `字段下拉`（来自 `db.Fields()`）→ `值输入` → `添加`
- 条件区：单列小列表展示已添加条件，选中按 Delete 删除，`重置` 清空条件并把下拉恢复默认
- 表格列（五元组拆分独立列，按之前要求）：
  时间 / 主机 / PID / 进程 / 用户 / 协议 / 源 IP / 源端口 / 目标 IP / 目标端口 / 域名 / 方向 / Geo / 完整性 / 规则 / 风险 / 详情
- 详情：最后一列「详情」+ 双击行，打开独立窗口（提升字段 + Sysmon 原始字段 + raw JSON）
- Sysmon 面板：`安装 / 重新安装`（二合一）、`卸载`、日志上限 GB（显示当前大小，保存即生效）、`启用 DNS` 复选、完整参数文本框（改后自动重装）
- 状态栏：`总计 N 行` | 状态提示 | `耗时 xx ms`

## 8. 交互细节

- 导入：点按钮弹系统 `IFileOpenDialog`（多选），窗口本身接受拖入 `.evtx`，拖入即导入
- 导出：复用 `ExportRows()` 流式写 CSV，进度和耗时写状态栏
- 首次启动检测 Sysmon（服务 + 日志四态判断），提示是否安装，安装输出仍打印到命令行/控制台
- 保留控制台子系统（不加 `-H=windowsgui`），保证 Sysmon 安装日志可见；GUI 与命令行共存

## 9. 构建

```
build.sh 增加：
  go-winres simply --icon audit/uiwin/app.ico --manifest gui --arch amd64,arm64 --out audit/rsrc
  GOOS=windows GOARCH=amd64 go1.20 build -trimpath -ldflags="-s -w" -o outputs/trace-audit_windows_amd64.exe ./audit
```

不加 `-H=windowsgui`；资源文件由 `go-winres` 在构建机生成（macOS 可直接跑，无需 windres）。

## 10. 不做 / 后续

- 暗色主题：不做（原生 Win7 无暗色体系，需整体自绘，收益低于成本）
- 列宽/列序记忆、多标签页：后续按需
- 32 位：SQLite 依赖限制，仍只出 64 位
