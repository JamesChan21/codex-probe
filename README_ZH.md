```
  ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗      ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝      ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 ██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ █████╗██████╔╝██████╔╝██║   ██║██████╔╝█████╗
 ██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ╚════╝██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
 ╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗      ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
```

<div align="center">

**Codex 凭证管理与接口诊断命令行工具**

[![Release](https://img.shields.io/github/v/release/yourname/codex-probe?style=flat-square)](../../releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)]()

[English](README.md) · [中文](README_ZH.md)

</div>

---

一键登录 · 查看用量 · 测试模型 · 导出 CSV，单二进制文件，支持 Windows / Linux / macOS。

---

## 安装

**直接下载（推荐）**

从 [Releases](../../releases) 下载对应平台的文件：

| 平台 | 文件名 |
|---|---|
| Linux x86-64 | `codex-probe-linux-amd64` |
| Linux ARM64 | `codex-probe-linux-arm64` |
| macOS Intel | `codex-probe-darwin-amd64` |
| macOS Apple Silicon | `codex-probe-darwin-arm64` |
| Windows x86-64 | `codex-probe-windows-amd64.exe` |

> **macOS 用户注意：** 本程序未经 Apple Developer 签名，下载后需手动解除隔离才能运行：
> ```bash
> xattr -d com.apple.quarantine codex-probe-darwin-*
> chmod +x codex-probe-darwin-*
> ./codex-probe-darwin-*
> ```

**从源码编译**

```bash
git clone https://github.com/yourname/codex-probe
cd codex-probe
go build -o codex-probe ./cmd/codex-probe/
```

---

## 快速上手

```bash
# 登录并保存凭证
codex-probe --login -o ./tokens/

# 就地续期凭证 JSON
codex-probe --renew ./tokens/my.json

# 查看剩余用量
codex-probe --status ./tokens/my.json

# 测试所有模型接口
codex-probe --apitest ./tokens/

# 用量 + 测试，同时导出 CSV
codex-probe --status --apitest --output result.csv ./tokens/

# 指定代理
codex-probe --proxy http://127.0.0.1:7890 --status ./tokens/my.json
```

---

## 参数说明

```
Usage:
  codex-probe [options] <file-or-dir>

Options:
  --login          OAuth PKCE 登录，监听 :1455 回调，写入凭证 JSON
  -o       <path>  --login 的输出文件或目录（与 --login 一起使用时必填）
  --renew          用 refresh_token 刷新凭证并回写 JSON
  --status         查询剩余用量（5小时窗口 + 每周窗口）
  --apitest        对每个模型发最小请求，报告可用性（--test 为别名）
  --output <path>  将结果写入 CSV 文件（须以 .csv 结尾）
  --proxy  <url>   代理地址，如 http://127.0.0.1:7890 或 socks5://...
                   传 "" 强制直连，不传则自动检测系统代理
  --help           显示帮助
```

**位置参数（`--renew` / `--status` / `--apitest` 必填）：**

| | 说明 |
|---|---|
| `<file>` | 单个凭证 JSON 文件 |
| `<dir>` | 目录 — 批量处理目录下所有 `*.json` 文件 |

**凭证 JSON 格式：**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "...",
  "account_id": "user-...",
  "email": "you@example.com"
}
```

---

## 代理检测优先级

不指定 `--proxy` 时，按以下顺序自动检测：

1. `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` 环境变量
2. macOS — `scutil --proxy`（系统网络偏好设置）
3. Windows — `HKCU\...\Internet Settings` 注册表
4. 以上均未检测到则直连

---

## CSV 输出列

**`--status`**

| 列名 | 说明 |
|---|---|
| `file` | 凭证文件路径 |
| `account_id` | 账号 ID |
| `email` | 邮箱 |
| `plan_type` | 套餐类型 |
| `5h_used_pct` | 5小时窗口已用百分比 |
| `5h_reset_at` | 5小时窗口重置时间 |
| `weekly_used_pct` | 每周窗口已用百分比 |
| `weekly_reset_at` | 每周窗口重置时间 |
| `upstream_status` | HTTP 状态码 |
| `error` | 错误信息（如有）|

**`--apitest`** — 每个 token 一行

| 列名 | 说明 |
|---|---|
| `file` | 凭证文件路径 |
| `account_id` | 账号 ID |
| `sample_models` | 随机抽取的 3 个模型名（`;` 分隔）|
| `available` | 至少 1 个模型响应成功则为 `true` |

---

## 实现原理

`codex-probe` 复刻了 [Codex CLI](https://github.com/openai/codex) 的 OAuth PKCE 授权流程：

1. 生成随机 `state` + PKCE `verifier / S256 challenge`
2. 使用 Codex CLI 的 `client_id` 打开 `https://auth.openai.com/oauth/authorize`
3. 监听 `localhost:1455/auth/callback` 等待浏览器回调
4. 用 `code + verifier` 换取 `access_token + refresh_token`
5. 解码 JWT 提取 `account_id` 和 `email`

遇到 401/403 时会自动用 `refresh_token` 续期，也可以用 `--renew` 显式强制刷新。

---

## License

MIT

---

## 致谢

- OAuth PKCE 流程与模型列表参考自 [QuantumNous/new-api](https://github.com/QuantumNous/new-api)

---

## 友情链接

[![LinuxDO](https://img.shields.io/badge/社区-Linux.do-blue?style=flat-square)](https://linux.do/)

欢迎前往 [linux.do](https://linux.do/) 交流讨论。
