# Prompt Guard

A lightweight HTTPS MITM proxy that intercepts prompts sent to AI coding assistants and APIs — flagging sensitive data before it leaves your machine.

## Why

AI tools like GitHub Copilot, ChatGPT, and Claude receive your full editor context. That context can contain API keys, passwords, SSNs, internal IP addresses, and other secrets — sent to third-party servers without you noticing. Prompt Guard sits between your tools and the AI APIs, inspects every prompt in real time, and alerts you when something sensitive is about to be sent.

## Features

- **HTTPS MITM proxy** — transparent interception using a local CA cert
- **Real-time inspection** — rules run on every prompt before it's forwarded
- **Web dashboard** — live feed of flagged prompts with matched snippets
- **12 built-in rules** — credentials, PII, tokens, private keys
- **Zero prompt blocking** — inspect-only by default, nothing is dropped
- **SQLite persistence** — full audit log across restarts
- **Single binary** — no runtime dependencies

## Targets

Intercepts prompts sent to:

| Service | Host |
|---|---|
| GitHub Copilot | `*.githubcopilot.com` |
| OpenAI | `api.openai.com` |
| Anthropic | `api.anthropic.com` |

All other HTTPS traffic is tunnelled through unchanged.

## Built-in Rules

| Rule | Severity |
|---|---|
| AWS Access Key (`AKIA…`) | High |
| AWS Secret Key | High |
| OpenAI API Key (`sk-…`) | High |
| Anthropic API Key (`sk-ant-…`) | High |
| GitHub Token (`ghp_`, `gho_`, …) | High |
| Private Key (PEM block) | High |
| Social Security Number | High |
| Credit Card Number | High |
| JWT Token | Medium |
| Generic Secret / Password assignment | Medium |
| Email Address | Low |
| Internal IP Address (RFC-1918) | Low |

## Requirements

- Go 1.21+
- macOS, Linux, or Windows

## Quickstart

```bash
git clone https://github.com/chaudharydeepak/prompt-guard
cd prompt-guard
go build -o prompt-guard .
./prompt-guard
```

On first run a local CA cert is generated and setup instructions are printed:

```
┌─────────────────────────────────────────┐
│           Prompt Guard starting         │
└─────────────────────────────────────────┘

CA cert:   /Users/you/.prompt-guard/ca.crt

Install CA (run once):
  sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain ~/.prompt-guard/ca.crt

Set proxy:
  export HTTP_PROXY=http://localhost:8080
  export HTTPS_PROXY=http://localhost:8080
  export NO_PROXY=localhost,127.0.0.1

Dashboard: http://localhost:7778
```

### Using with VS Code Copilot

Launch VS Code from the same terminal where you exported the proxy env vars:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
code .
```

Or set the proxy directly in VS Code settings (`Cmd+,`):

```json
"http.proxy": "http://localhost:8080",
"http.proxyStrictSSL": true
```

### Using with curl / scripts

```bash
curl --proxy http://localhost:8080 https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## Options

```
--port       Proxy port (default: 8080)
--web-port   Dashboard port (default: 7778)
--ca-dir     Directory for CA cert, key, and database (default: ~/.prompt-guard)
```

## Architecture

```
Your app (VS Code, curl, etc.)
  → HTTP_PROXY / HTTPS_PROXY
    → prompt-guard proxy (:8080)
      ├── Non-target hosts → blind tunnel (unchanged)
      └── Target hosts (OpenAI, Anthropic, Copilot)
            → TLS MITM (local CA cert)
              → parse JSON body → extract prompt text
                → run rules → if match: store in SQLite
                  → forward to real API → return response
                    → web dashboard (:7778) reads SQLite
```

```
prompt-guard/
├── main.go              CLI entrypoint
├── proxy/
│   ├── ca.go            Local CA cert generation and leaf cert signing
│   ├── proxy.go         HTTP CONNECT handler, TLS MITM, request forwarding
│   └── intercept.go     Prompt extraction from OpenAI / Anthropic JSON bodies
├── inspector/
│   ├── engine.go        Rule matching engine
│   └── rules.go         Built-in rules (regex + metadata)
├── store/
│   └── store.go         SQLite persistence
└── web/
    └── web.go           Web dashboard (embedded HTML)
```

## License

AGPL
