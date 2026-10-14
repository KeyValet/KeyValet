# Windows 可选 SignPath 接线准备

2026-10-14：Foundation 申请因项目公开知名度不足而未获批。维护者决定 Windows 正式发布不要求代码签名；安装器、helper、agent、MCP worker 与 relay 按安装文件身份、服务/owner SID 和受保护路径权限认证，不再因未签名拒绝本地或远程功能。已准备的签名输入保留为可选工具，尚未启用 SignPath 提交。当前政策见 [Windows 支持](windows.md)。

## 已准备

- `.github/workflows/windows-signing-input.yml` 在 GitHub 托管的 x64／ARM64 runner 上构建七个原生 EXE。
- `rust/windows-version.rs` 使用 Windows SDK 的资源编译器嵌入 ProductName、版本和 OriginalFilename，沿用原有 Windows manifest；没有新增 Rust 依赖。
- `scripts/prepare-windows-signing.ps1` 核对版本、PE 架构、七个固定文件名和未签名状态，输出 SHA256 输入清单。
- `.github/signpath/windows-artifact.xml` 固定列出七个 EXE，并要求 ProductName=KeyValet。它供审核后配置使用，当前没有向 SignPath 提交请求。

本地准备命令：

```powershell
.\scripts\prepare-windows-signing.ps1 `
  -BinaryDirectory C:\path\to\native\release `
  -OutputDirectory C:\path\to\fresh-signing-input `
  -Architecture x64
```

本地产物用于开发验收。Foundation 的可信构建流程要求先上传 GitHub workflow artifact，再由其 GitHub connector 校验来源；本地 VM 构建不冒充该来源。[GitHub 集成文档](https://docs.signpath.io/trusted-build-systems/github)

## 将来选择签名时的可选接线

1. 在 Foundation 提供的组织／项目中配置官方 GitHub App、可信仓库、托管 runner、签名策略与审批者；维护者账户启用 MFA。
2. 将组织 ID、项目／策略／artifact configuration slug 配置到受保护的 release 环境，API token 仅放环境 secret。接入官方 `submit-signing-request` action，绑定本次上传的 artifact ID，等待完成后取回产物。[官方 action 参数](https://docs.signpath.io/trusted-build-systems/github#action-input-parameters)
3. 检查实际证书、publisher 与项目绑定方式。签名用于分发身份和文件完整性；已安装进程的权限仍按 SID、固定文件身份、受保护 ACL 和服务创建的 worker 验证。
4. 对返回的七个 EXE 检查 Authenticode、时间戳、证书链、项目身份和 PE 元数据，重新生成 ZIP／SHA256SUMS；证书有效不等于正式包已经验收。
5. 在正式包上补 Windows 注册、配对、公网实际凭证请求、吊销、SmartScreen 和证书失效验收，再由维护者发布。

Foundation 证书的 publisher 为基金会；这与 Simvito 公司证书的分发身份不同。[Foundation 条款](https://signpath.org/terms)
