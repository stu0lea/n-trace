# Third-Party Notices

N-trace 自有源代码采用 MIT License。以下组件、数据和可执行文件不属于 N-trace 的 MIT 授权范围，仍分别遵循其上游许可证和条款。

本文件用于说明主要第三方组件，不替代各项目携带的完整许可证文本。

## Microsoft Sysmon

- 组件：Sysmon 可执行文件
- 位置：`audit/data/sysmon/`
- 来源：Microsoft Sysinternals
- 条款：Microsoft Sysinternals Software License Terms
- 链接：https://learn.microsoft.com/sysinternals/license-terms

Sysmon 是 Microsoft 提供的第三方软件，不属于 N-trace 自有代码。N-trace 的 MIT License 不适用于 Sysmon。复制、分发或商业打包 Sysmon 前，应单独确认 Microsoft 当前许可条款。

## ip2region

- 组件：Go 绑定和 IP 归属地数据
- 来源：https://github.com/lionsoul2014/ip2region
- 许可证：Apache License 2.0

## Windigo

- 组件：Windows Win32 UI 和系统 API 绑定
- 来源：https://github.com/rodrigocfd/windigo
- 许可证：MIT

## modernc.org/sqlite

- 组件：纯 Go SQLite 驱动
- 来源：https://gitlab.com/cznic/sqlite
- 许可证：BSD-3-Clause

## Velocidex EVTX

- 组件：EVTX 解析
- 来源：https://github.com/Velocidex/evtx
- 许可证：Apache License 2.0

## Velocidex ordereddict

- 组件：事件字段字典
- 来源：https://github.com/Velocidex/ordereddict
- 许可证：Apache License 2.0

## Go dependencies

`go.mod` 和 `go.sum` 中列出的其他直接及间接依赖分别遵循其模块上游许可证。发布二进制或源码包时，应保留相应许可证和版权声明。
