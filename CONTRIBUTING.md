# Contributing

感谢参与 N-trace。

## Before submitting

- 使用最小可复现数据，不要提交真实终端日志、凭据、用户名、主机名或其他敏感信息。
- Bug 修复应尽量附带回归测试。
- 涉及查询语法、数据库 schema、实时断点或 Sysmon 操作的改动，需要说明兼容性和迁移影响。
- 提交前运行：

```powershell
$env:CGO_ENABLED = "0"
go test -count=1 .\audit
```

## Contribution licensing

N-trace 当前自有代码采用 MIT License，并保留未来单独提供企业模块或商业授权的可能。

在提交实质性外部代码前，请先联系仓库维护者确认贡献者许可协议（CLA）。未经确认的外部贡献可能无法合并。提交 Pull Request 即表示你有权提交相关代码，并同意项目保留在 MIT 之外进行商业授权所需的权利。

## Third-party content

不要提交无权再发布的二进制、日志数据、IP 数据库、Sysmon 安装包或其他第三方内容。新增依赖时必须同步更新 `THIRD_PARTY_NOTICES.md`。
