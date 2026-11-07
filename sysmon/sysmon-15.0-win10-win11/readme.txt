Sysmon 的核心应急价值在于：通过进程级网络连接与 DNS 日志，把“谁在连哪里”准确归因到具体进程，支撑快速溯源。

#  微软官方下载 https://learn.microsoft.com/zh-cn/sysinternals/downloads/sysmon
# 目前新版本不支持win7等老系统

# 重要！！！！使用管理员权限运行CMD

# 默认+全量网络连接
sysmon64.exe -accepteula -i -n

# 将Sysmon日志设置为2GB最大大小
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:2147483648

#查看Sysmon日志

Sysmon将事件写入专用事件日志通道。活动可以通过事件查看器在本地查看
按 Win + R，输入 eventvwr.msc，回车，应用程序和服务日志 → Microsoft → Windows → Sysmon → Operational

# 将 Sysmon 日志导出到文件
wevtutil epl "Microsoft-Windows-Sysmon/Operational" D:\sysmon_export_full.evtx
或者
点击事件查看器右侧操作栏的 “保存所有事件为...”（或在日志上右键 → “将已保存的日志另存为...”）







---以下是非必要参数

# 最新配置下载https://github.com/SwiftOnSecurity/sysmon-config

# 自定义安全策略，可以减少噪音，但是捕获日志不全，适合长期运行，不适合应急
sysmon64.exe -accepteula -i sysmonconfig-export.xml

#更新配置
sysmon64.exe -c sysmonconfig-export.xml

# 将Sysmon日志设置为1GB最大大小

wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824

# 停止记录日志
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /enabled:false

# 继续记录日志
wevtutil set-log "Microsoft-Windows-Sysmon/Operational" /enabled:true

# 直接卸载服务
sysmon.exe -u 

# 查询服务状态
sc query Sysmon64

# 将启动类型改为"禁用"
sc config Sysmon64 start= disabled

# 停止当前运行的服务
sc stop Sysmon64


#查看Sysmon日志

Sysmon将事件写入专用事件日志通道。活动可以通过事件查看器在本地查看
按 Win + R，输入 eventvwr.msc，回车，应用程序和服务日志 → Microsoft → Windows → Sysmon → Operational

# 将 Sysmon 日志导出到文件
wevtutil epl "Microsoft-Windows-Sysmon/Operational" D:\sysmon_export_full.evtx
或者
点击事件查看器右侧操作栏的 “保存所有事件为...”（或在日志上右键 → “将已保存的日志另存为...”）

# 按时间范围导出（只导出最近 N 小时/天）
wevtutil epl "Microsoft-Windows-Sysmon/Operational" D:\sysmon_recent.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
如果想导出一周：604800000（7天）

导出所有事件为 CSV
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Export-Csv -Path "D:\sysmon_export.csv" -NoTypeInformation

导出特定事件 ID（比如只导出事件 1：进程创建）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" | Export-Csv -Path "D:\sysmon_event1.csv" -NoTypeInformation

# 查看最近的Sysmon事件
wevtutil qe Microsoft-Windows-Sysmon/Operational /c:10 /f:text

# 清除 Sysmon 日志（需要管理员）
wevtutil cl Microsoft-Windows-Sysmon/Operational


# 命令说明
-i [配置]	安装服务和驱动程序，可选配置配置文件
-c [配置]	更新已安装的Sysmon的配置，如果没有指定文件，则打印当前配置
-u [力量]	卸载服务和驱动程序；即使删除失败，也使用“强制”删除
-接受	自动接受许可协议（默色安装需要）
-h [算法]	指定哈希算法（MD5、SHA1、SHA256、IMPHASH或*）
-n [名字]	记录网络连接；可选择指定进程名称过滤器
-l	日志模块（DLL）加载事件
-s	打印配置模式定义