<p align="center">
  <img width="256" height="256" alt="Gemini_Generated_Image_6p04mm6p04mm6p04" src="https://github.com/user-attachments/assets/512cd1d8-93af-40dc-acde-6e7daa339493" />
</p>
<div align="center">

**Codex 凭证管理与接口诊断命令行工具**

[![Release](https://img.shields.io/github/v/release/yourname/codex-probe?style=flat-square)](../../releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)]()

[English](README.md) · [中文](README_ZH.md)

</div>

`codex-probe` 是一个单文件 CLI，用来集中管理 Codex token 的登录、续期、额度查询、接口测试，以及按需同步到 Supabase。

## 项目简介

<p align="center">
  <img width="80%" alt="logo" src="https://github.com/user-attachments/assets/9bd3c05b-5274-4bb3-b504-c18a52891181" />
</p>

这个工具把一堆偏底层的参数，整理成一套更顺手的日常 token 管理流程。

功能特性：

- `--login`：走一遍网页登录流程，把 token 保存到本地 JSON
- `--renew`：给单个 token 文件或整个目录批量续期
- `--status`：查询现有 token 的额度窗口
- `--apitest`：用最小请求探测模型接口能不能用
- `--sync`：把本地 token 加密后同步到 Supabase，也能从云端拉回本地
- `--output`：把 `--status` 和 `--apitest` 结果导出成 CSV
- `--proxy`：手动指定代理，或者直接走系统代理检测

详细说明见：

- [docs/advanced_ZH.md](docs/advanced_ZH.md)
- [docs/supabase_ZH.md](docs/supabase_ZH.md)

## 安装

可直接从 [Releases](../../releases) 下载预编译文件。

| 平台 | 文件名 |
|---|---|
| Linux x86-64 | `codex-probe-linux-amd64` |
| Linux ARM64 | `codex-probe-linux-arm64` |
| macOS Intel | `codex-probe-darwin-amd64` |
| macOS Apple Silicon | `codex-probe-darwin-arm64` |
| Windows x86-64 | `codex-probe-windows-amd64.exe` |

也可以从源码编译：

```bash
git clone https://github.com/yourname/codex-probe
cd codex-probe
go build -o codex-probe ./cmd/codex-probe/
```

macOS 首次运行如果被系统拦截，可先去掉隔离属性：

```bash
xattr -d com.apple.quarantine codex-probe-darwin-*
chmod +x codex-probe-darwin-*
./codex-probe-darwin-*
```

## 快速上手

首次运行前，先复制示例配置：

```bash
cp ./config.example.json ./config.json
```

常用命令：

```bash
# 登录并保存 token 文件
codex-probe --login -o ./tokens/

# 就地续期单个 token 文件
codex-probe --renew ./tokens/me.json

# 查看额度
codex-probe --status ./tokens/me.json

# 测试模型可用性
codex-probe --apitest ./tokens/

# 与 Supabase 同步本地 token 文件
codex-probe --sync
```

## 本地配置

默认会读取可执行文件同级的 `config.json`。建议直接从 [config.example.json](config.example.json) 开始。

```json
{
  "renew_before_expiry_days": 3,
  "sync_url": "https://<project>.supabase.co",
  "sync_api_key": "<publishable-key>",
  "sync_aes_gcm_key": "<64-char-hex>",
  "sync_dir": "./tokens"
}
```

- `renew_before_expiry_days`：距离过期多少天内，工具会认为该续期了
- `sync_url`：Supabase 项目地址
- `sync_api_key`：Supabase publishable key
- `sync_aes_gcm_key`：本地 AES-256-GCM 密钥，可用 `openssl rand -hex 32` 生成
- `sync_dir`：`--sync` 使用的本地 token 目录

Supabase 用 Free Plan 就够用了。

如果你想看 Supabase 控制台配置、本地配置字段详解、续期机制、代理检测、CSV 格式和工作原理，请看：

- [docs/advanced_ZH.md](docs/advanced_ZH.md)
- [docs/supabase_ZH.md](docs/supabase_ZH.md)
- [supabase.sql](supabase.sql)

## License

MIT

## Community

[![LinuxDO](https://img.shields.io/badge/社区-Linux.do-blue?style=flat-square)](https://linux.do/)

欢迎前往 [linux.do](https://linux.do/) 交流讨论。
