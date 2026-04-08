```
          ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗      ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
         ██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝      ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
         ██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ █████╗██████╔╝██████╔╝██║   ██║██████╔╝█████╗
         ██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ╚════╝██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
         ╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗      ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
          ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
```

<div align="center">

**Codex Credential & Diagnostics CLI**

[![Release](https://img.shields.io/github/v/release/yourname/codex-probe?style=flat-square)](../../releases)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=flat-square)]()

[English](README.md) · [中文](README_ZH.md)

</div>

---

Login · check quota · test models · export CSV — all in one binary. Works on Windows / Linux / macOS.

---

## Install

**Pre-built binary (recommended)**

Download from [Releases](../../releases):

| Platform | File |
|---|---|
| Linux x86-64 | `codex-probe-linux-amd64` |
| Linux ARM64 | `codex-probe-linux-arm64` |
| macOS Intel | `codex-probe-darwin-amd64` |
| macOS Apple Silicon | `codex-probe-darwin-arm64` |
| Windows x86-64 | `codex-probe-windows-amd64.exe` |

> **macOS users:** The binary is not signed with an Apple Developer certificate. You need to remove the quarantine attribute before running:
> ```bash
> xattr -d com.apple.quarantine codex-probe-darwin-*
> chmod +x codex-probe-darwin-*
> ./codex-probe-darwin-*
> ```

**Build from source**

```bash
git clone https://github.com/yourname/codex-probe
cd codex-probe
go build -o codex-probe ./cmd/codex-probe/
```

---

## Quick Start

```bash
# Login and save credential
codex-probe --login -o ./tokens/

# Refresh credential JSON in place
codex-probe --renew ./tokens/my.json

# Force refresh credential JSON in place
codex-probe --renew -f ./tokens/my.json

# Check remaining quota
codex-probe --status ./tokens/my.json

# Test all model endpoints
codex-probe --apitest ./tokens/

# Use a custom config file
codex-probe --config ./config.json --renew ./tokens/

# Quota + apitest, export to CSV
codex-probe --status --apitest --output result.csv ./tokens/

# Use proxy
codex-probe --proxy http://127.0.0.1:7890 --status ./tokens/my.json
```

---

## Options

```
Usage:
  codex-probe [options] <file-or-dir>

Options:
  --login          OAuth PKCE login, listen on :1455, write credential JSON
  -o       <path>  Output file or directory for --login (required with --login)
  --config <path>  Config file path; default is config.json next to the executable
  --renew          Refresh credential(s) with refresh_token and write back JSON by policy
  -f               Force refresh when used with --renew
  --status         Query remaining quota (5h window + weekly window)
  --apitest        Test availability of every model endpoint (--test is an alias)
  --output <path>  Write results to a CSV file (must end in .csv)
  --proxy  <url>   Proxy URL  e.g. http://127.0.0.1:7890  or  socks5://...
                   Pass "" to force direct connection
                   Omit flag to auto-detect system proxy
  --help           Show this help
```

**Positional argument (required for `--renew` / `--status` / `--apitest`):**

| | Description |
|---|---|
| `<file>` | A single credential JSON file |
| `<dir>` | Directory — processes all `*.json` files inside |

**Credential JSON format:**

```json
{
  "id_token": "eyJ...",
  "access_token": "eyJ...",
  "refresh_token": "...",
  "account_id": "user-...",
  "email": "you@example.com",
  "last_refresh": "2026-04-08T10:11:18Z",
  "type": "codex",
  "expired": "2026-04-18T10:11:18Z"
}
```

---

## Configuration

By default, `codex-probe` loads `config.json` from the same directory as the executable.

If the file does not exist, it will be created automatically with:

```json
{
  "renew_before_expiry_days": 3
}
```

You can override it with `--config <path>`.

---

## Proxy Detection Order

When `--proxy` is not specified, the following are tried in order:

1. `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` environment variables
2. macOS — `scutil --proxy`
3. Windows — `HKCU\...\Internet Settings` registry
4. Direct connection (fallback)

---

## CSV Output

**`--status`**

| Column | Description |
|---|---|
| `file` | Credential file path |
| `account_id` | Account ID |
| `email` | Email |
| `plan_type` | Plan type |
| `5h_used_pct` | 5-hour window usage % |
| `5h_reset_at` | 5-hour window reset time |
| `weekly_used_pct` | Weekly window usage % |
| `weekly_reset_at` | Weekly window reset time |
| `upstream_status` | HTTP status code |
| `error` | Error message if any |

**`--apitest`** — one row per token

| Column | Description |
|---|---|
| `file` | Credential file path |
| `account_id` | Account ID |
| `sample_models` | 3 randomly sampled model names (`;`-separated) |
| `available` | `true` if at least one sampled model responded successfully |

---

## How It Works

`codex-probe` replicates the [Codex CLI](https://github.com/openai/codex) OAuth PKCE flow:

1. Generates random `state` + PKCE `verifier / S256 challenge`
2. Opens `https://auth.openai.com/oauth/authorize` with Codex CLI's `client_id`
3. Listens on `localhost:1455/auth/callback` for the browser redirect
4. Exchanges `code + verifier` → `access_token + refresh_token + id_token`
5. Decodes JWT to extract `account_id` and `email`

Refresh behavior:

1. `--renew` checks each credential file independently
2. A credential is refreshed when any of these is true:
   - `-f` is set
   - `id_token` is missing
   - `expired` is missing or invalid
   - the token expires within `renew_before_expiry_days`
3. Otherwise the credential is skipped
4. Each refresh retries up to 3 times internally
5. `--status` also auto-refreshes on 401/403 using the same retry limit

---

## License

MIT

---

## Credits

- OAuth PKCE flow & model list referenced from [QuantumNous/new-api](https://github.com/QuantumNous/new-api)

---

## Community

[![LinuxDO](https://img.shields.io/badge/Community-Linux.do-blue?style=flat-square)](https://linux.do/)

Discuss, share tips, and get help at [linux.do](https://linux.do/).
