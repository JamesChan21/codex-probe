<p align="center">
  <img width="256" height="256" alt="Gemini_Generated_Image_6p04mm6p04mm6p04" src="https://github.com/user-attachments/assets/512cd1d8-93af-40dc-acde-6e7daa339493" />
</p>

<div align="center">

**Codex Credential & Diagnostics CLI**

[![Release](https://img.shields.io/github/v/release/yourname/codex-probe?style=flat-square)](../../releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)]()

[English](README.md) · [中文](README_ZH.md)

</div>

`codex-probe` is a single-binary CLI for Codex token login, renewal, quota checks, API smoke tests, and optional Supabase sync.

## Project Overview

<p align="center">
  <img width="80%" alt="logo" src="https://github.com/user-attachments/assets/9bd3c05b-5274-4bb3-b504-c18a52891181" />
</p>

`codex-probe` turns the raw CLI flags into a small credential workflow you can actually operate day to day.

Features:

- `--login`: start OAuth PKCE login and write a token JSON locally
- `--renew`: refresh one token file or a whole directory in place
- `--status`: read remaining quota windows from existing token files
- `--apitest`: send lightweight requests to verify model availability
- `--sync`: encrypt local token files and sync them with Supabase
- `--output`: export `--status` and `--apitest` results as CSV
- `--proxy`: use a fixed proxy or fall back to system proxy detection

For detailed guides, see:

- [docs/advanced.md](docs/advanced.md)
- [docs/supabase.md](docs/supabase.md)

## Install

Pre-built binaries are available in [Releases](../../releases).

| Platform | File |
|---|---|
| Linux x86-64 | `codex-probe-linux-amd64` |
| Linux ARM64 | `codex-probe-linux-arm64` |
| macOS Intel | `codex-probe-darwin-amd64` |
| macOS Apple Silicon | `codex-probe-darwin-arm64` |
| Windows x86-64 | `codex-probe-windows-amd64.exe` |

Build from source:

```bash
git clone https://github.com/yourname/codex-probe
cd codex-probe
go build -o codex-probe ./cmd/codex-probe/
```

On macOS, remove quarantine before first run if needed:

```bash
xattr -d com.apple.quarantine codex-probe-darwin-*
chmod +x codex-probe-darwin-*
./codex-probe-darwin-*
```

## Quick Start

Copy the example config before first run:

```bash
cp ./config.example.json ./config.json
```

Common commands:

```bash
# Login and save token files
codex-probe --login -o ./tokens/

# Renew one token file in place
codex-probe --renew ./tokens/me.json

# Check quota
codex-probe --status ./tokens/me.json

# Test model availability
codex-probe --apitest ./tokens/

# Encrypt and sync local token files with Supabase
codex-probe --sync
```

## Local Config

By default, `codex-probe` loads `config.json` next to the executable. Start from [config.example.json](config.example.json).

```json
{
  "renew_before_expiry_days": 3,
  "sync_url": "https://<project>.supabase.co",
  "sync_api_key": "<publishable-key>",
  "sync_aes_gcm_key": "<64-char-hex>",
  "sync_dir": "./tokens"
}
```

- `renew_before_expiry_days`: renew when the token is close to expiry
- `sync_url`: Supabase project URL
- `sync_api_key`: Supabase publishable key
- `sync_aes_gcm_key`: local AES-256-GCM key generated with `openssl rand -hex 32`
- `sync_dir`: local directory used by `--sync`

Supabase Free Plan is enough for this workflow.

For Supabase setup, local config details, renew behavior, proxy detection, CSV format, and internals, see:

- [docs/advanced.md](docs/advanced.md)
- [docs/supabase.md](docs/supabase.md)
- [supabase.sql](supabase.sql)

## License

MIT

## Community

[![LinuxDO](https://img.shields.io/badge/Community-Linux.do-blue?style=flat-square)](https://linux.do/)

Discuss usage and issues at [linux.do](https://linux.do/).
