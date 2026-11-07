# N-trace 开发与架构说明

本目录包含 N-trace 的主要 Go 源码、Windows 原生界面、Web 调试界面、内置数据和资源文件。

用户安装和使用说明请先阅读仓库根目录的 [README.md](../README.md)。

## 技术栈

- Go 1.20
- SQLite WAL，驱动为 `modernc.org/sqlite`
- FTS5 trigram 全文索引
- Windows 原生 Win32 UI，使用 `github.com/rodrigocfd/windigo`
- EVTX 解析使用 `www.velocidex.com/golang/evtx`
- IP 归属地使用内置 `ip2region`
- Sysmon 日志通过 `wevtutil` 轮询读取

## 启动流程

1. 解析命令行和数据目录。
2. 加载或创建 `config.ini`。
3. 初始化按月归档的应用日志。
4. 获取单实例锁。
5. 打开内置 IP 库和 SQLite 数据库。
6. 导入命令行指定的 `.evtx`。
7. Windows 默认进入原生 UI；其他平台或指定 `-web` 时进入浏览器界面。

原生 UI 启动后会检测 Sysmon 状态，并询问是否安装或修复。实时读取默认自动开启。

## 主要模块

| 文件 | 职责 |
|---|---|
| `main.go` | 参数解析、初始化、导入、原生/Web UI 选择 |
| `config.go` | `config.ini` 加载、校验和保存 |
| `log.go` | GUI 运行日志、按月归档和保留清理 |
| `parse.go` | EVTX 读取和 Sysmon 原始事件解析 |
| `model.go` | 连接、进程、DNS 数据模型和风险规则 |
| `db.go` | SQLite schema、迁移、入库、查询、统计和 FTS |
| `live.go` | 实时轮询循环、断点、补读和状态统计 |
| `live_windows.go` | `wevtutil` 查询实现 |
| `sysmon_windows.go` | Sysmon 状态、安装、卸载和日志配置 |
| `export.go` | 当前页签筛选结果的 CSV 导出 |
| `source_delete.go` | 删除本地导入日志源及其数据 |
| `uiwin_app_windows.go` | 原生主窗口、控件布局和业务联动 |

## SQLite 结构

### 数据表

- `conn`：EID 3 网络连接。
- `dns`：EID 22 DNS 查询。
- `process_event`：EID 1 进程创建和 EID 5 进程结束原始事件。
- `process_list`：按进程 GUID 聚合的进程视图，供进程页签快速分页。
- `process_ip`：进程到目标 IP 的集合，用于目的 IP 数统计。
- `file`：本地导入日志源清单。
- `rawfield`：Sysmon 原始字段索引。
- `app_meta`：数据库迁移版本等内部元数据。

### 索引

连接、DNS 和进程聚合表均有面向时间倒序分页的复合索引。连接全文搜索使用 `conn_fts`，字段包括：

```text
image, cmdline, dst_host, geo, dst_ip
```

### 唯一性

- 连接：`(guid, ts, dst_ip, dst_port, proto)`
- 进程事件：`(guid, event_id, ts)`
- DNS：规范化后的时间、主机、GUID、域名、结果和状态

入库使用 `INSERT OR IGNORE`，重复补读不会创建重复记录。

## 实时读取

实时读取只查询以下 Sysmon 事件：

```text
EventID=1 or EventID=3 or EventID=22
```

断点保存在数据目录的 `live-last-id.txt`，内容为最后成功处理的 `EventRecordID`。

处理顺序：

1. 读取断点。
2. 读取当前通道最新记录号。
3. 断点有效时从断点之后补读。
4. 断点缺失、为 0 或大于最新记录号时，从当前日志最早匹配记录开始。
5. 每批成功入库后原子更新断点。
6. 补读追平后进入增量轮询。

暂停和关闭只停止采集 goroutine，不删除断点。

## 查询引擎

`db.go` 中的 `compile`、`compileDNS` 和 `compileProcess` 负责把查询文本转换为带参数的 SQL。

关键约束：

- 字段名必须通过白名单解析，避免 SQL 注入。
- 条件之间必须显式写 `and`。
- 支持 `or`、`not`、`-`、括号、字段比较和通配。
- 原始 Sysmon 字段通过 JSON 提取，但只能使用已登记的字段。
- 时间字段先转换为 Unix 毫秒再比较。

## 共享虚拟表

连接、进程和 DNS 使用 `uiwin_shared_virtual_windows.go` 中的 owner-data 虚拟表实现。

- 每块 256 条。
- 最多缓存 16 块。
- 只查询当前可见块，避免一次加载全部结果。
- 刷新时保留横向滚动位置，并按比例恢复纵向位置。
- 快照 ID 或快照时间保证刷新期间分页结果稳定。
- 选中行不会因为实时刷新被主动清除。

连接表使用数据库最大 ID 作为快照边界；进程和 DNS 使用快照时间。

## 原生 UI

原生 UI 位于 `uiwin_*_windows.go`。

- 页面主体使用连接、进程、DNS 三个 Tab。
- 顶部语法框、字段条件、热门数据和刷新频率随当前 Tab 切换。
- 表格右键按单元格字段添加 `AND` / `OR` 条件。
- 数据统计弹窗根据当前 Tab 使用不同统计模型。
- 日志源管理使用独立模态窗口。
- Sysmon 安装、卸载等操作通过独立管理员任务进程执行。

原生 UI 只在 Windows 下编译；其他平台使用 `ui_native_other.go` 和 Web UI。

## 风险计算

连接风险在 `model.go` 中计算：

- `R1` 非常规端口外联
- `R2` 非浏览器访问 Web 端口
- `R3` 临时/下载目录进程外联
- `R4` 直接连接公网 IP 且没有域名
- `R5` 短时间内大量外联目标
- `R6` 连接境外 IP

DNS 风险：

- `D1` 解析境外 IP
- `D2` 查询失败
- `D3` 无解析结果

风险只用于辅助排查，不应直接等同于恶意判定。

## 数据目录

开发运行时，默认使用仓库 `outputs/n-trace-data`：

```text
outputs/n-trace-data/
  audit.db
  config.ini
  live-last-id.txt
  sysmon-dns.xml
  trace-audit.log
```

测试应使用 `t.TempDir()`，不要在测试中写入默认数据目录。

## 测试与构建

```powershell
$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go test -count=1 .\audit
```

完整多平台构建：

```bash
./build.sh
```

`build.sh` 会临时复制 Windows manifest/resources 到 `audit/`，构建结束后自动清理，避免 `go test` 被管理员清单提权。

## 第三方许可

本仓库自有代码使用 MIT License。内置 Sysmon、IP 库和 Go 依赖保留各自许可证，具体见仓库根目录的 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。
