# Trace-Audit

基于 Sysmon 的网络连接审计工具。单个可执行文件、完全离线，导入 `.evtx` 后在本地网页里检索、统计和导出全部网络连接；Windows 下检测到 Sysmon 日志会自动开始实时采集。

## 功能

- 连接审计：五元组（协议 / 源 IP / 源端口 / 目的 IP / 目的端口）分列展示，附带进程、用户、域名、归属地与风险标记。
- 检索筛选：全字段支持，`and` / `or` / 取反 / 括号分组；也可用字段下拉直接加条件，不用手写表达式。
- 实时采集：自动读取 `Microsoft-Windows-Sysmon/Operational`，EID 1 / 3 / 22 联动补全命令行与域名。
- 风险规则：非常规端口外联、非浏览器访问 Web 端口、临时目录进程外联、直连公网 IP、短时间大量外联。
- 导出 CSV：导出当前筛选结果，UTF-8 带 BOM，Excel 直接打开。
- 内置 Sysmon：按系统版本自动选择 10.2 / 13.30 / 15.0 安装包，界面可安装、重装、卸载和调整日志上限。
- 浅色 / 暗色主题，默认浅色。

## 产物

| 目标 | 架构 | 产物 |
|---|---|---|
| Windows 10 / 11、Server 2016+ | amd64 / arm64 | `trace-audit_windows_amd64.exe` / `_arm64.exe` |
| macOS | amd64 / arm64 | `trace-audit_darwin_amd64` / `_arm64` |
| Linux | amd64 | `trace-audit_linux_amd64` |

Windows 版为单文件静态编译，内置 Sysmon 安装包与离线 IP 库，无需联网或额外运行库。

## 快速开始

```bash
# 启动（自动打开浏览器，数据存到程序目录 trace-audit-data/）
trace-audit_windows_amd64.exe

# 启动前先导入日志（文件或目录，目录只取 .evtx）
trace-audit_windows_amd64.exe D:\case\
```

也可以启动后点界面右上角「导入 evtx」，通过文件选择框或多选、拖拽导入。

## 构建

```bash
./build.sh
```

产物输出到 `outputs/`。Windows 版使用 Go 1.20 构建，以兼容 Win7 / Server 2008；其他平台使用本机 Go。

## 文档

完整用法、检索语法、Sysmon 版本对照与已知限制见 [audit/README.md](audit/README.md)。
