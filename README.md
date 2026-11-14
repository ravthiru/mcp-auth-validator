# mcp-auth-validator

[![License: MIT](https://shields.io)](https://opensource.org)
[![MCP Spec](https://shields.io)](https://modelcontextprotocol.io)
[![TypeScript](https://shields.io)](https://typescriptlang.org)

An automated OAuth 2.1 compliance and adversarial security testing CLI for **Model Context Protocol (MCP)** server implementers.

`mcp-auth-validator` acts as an automated, adversarial OAuth 2.1 client that probes your MCP server against the [MCP Authorization Specification](https://modelcontextprotocol.io), catching silent security bugs—such as token passthrough, missing `401` challenges, and DNS rebinding vulnerabilities—before you ship to production.

---

## Features

- **Discovery & Metadata Auditing (`RFC 9728` & `RFC 8414`):**
  - Verifies unauthenticated requests return `HTTP 401` with a valid `WWW-Authenticate: Bearer resource_metadata="..."` header.
  - Validates Protected Resource Metadata (PRM) schema and confirms the `resource` field matches your server's canonical URL.
  - Confirms Authorization Server metadata advertises `S256` PKCE support.
- **Adversarial Token Testing (Built-in Mock IdP):**
  - Spins up an ephemeral local OAuth 2.1 / JWKS server for zero-config CI/CD testing.
  - Tests rejection (`401`) of valid JWTs issued for a **different audience** (`aud` mismatch / confused deputy protection).
  - Tests rejection of expired tokens (`exp`), future `nbf` claims, tampered signatures, and `alg: none` headers.
  - Verifies query-string tokens (`?access_token=...`) are rejected.
  - Tests step-up authorization and scope enforcement (`403 Forbidden` with `insufficient_scope`).
- **Transport & Protocol Hygiene:**
  - Sends spoofed `Origin` headers to verify DNS rebinding protection (`403` rejection).
  - Flags non-HTTPS metadata URLs on remote endpoints.

---

## Quick Start

Run directly with `npx` without installing globally:

### 1. Passive Check (Live or Staging Server)
Audits discovery headers, `.well-known` metadata schemas, and `Origin` header enforcement without needing credentials:

```bash
npx mcp-auth-validator check https://example.com
```

### 2. Full Adversarial Suite (CI/CD Mode)
Starts an ephemeral local mock IdP (default `http://localhost:9999`), mints valid and malformed JWTs on the fly, and runs end-to-end MCP handshake and security boundary tests:

```bash
npx mcp-auth-validator test-suite http://localhost:3000/mcp
```

> **Note:** For `test-suite` mode, configure your local/staging MCP server to trust the mock IdP issuer (`http://localhost:9999`) or pass `--idp-port <port>` to match your configuration.

---

## CLI Usage & Options

```text
Usage: mcp-auth-validator [command] [options] <mcp-url>

Commands:
  check <mcp-url>         Run passive discovery, metadata, and transport checks
  test-suite <mcp-url>    Run full active & adversarial token suite with mock IdP
  mock-idp                Start the standalone mock OAuth 2.1 / JWKS server

Options:
  --idp-port <number>     Port for the ephemeral mock IdP (default: 9999)
  --token <jwt>           Provide a custom bearer token for live IdP testing
  --scope <string>        Required scope to test step-up / 403 boundaries
  --json                  Output machine-readable JSON report (for CI/CD)
  -h, --help              Display help for command
```

### Example CI/CD Integration (GitHub Actions)

```yaml
name: MCP Auth Compliance
on: [push, pull_request]

jobs:
  validate-auth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Start MCP Server
        env:
          OAUTH_ISSUER: http://localhost:9999
        run: npm run start:server &

      - name: Run MCP Auth Validator
        run: npx mcp-auth-validator test-suite http://localhost:3000/mcp --json
```

---

## Validation Checklist

| Check ID | Category | Description | Spec Reference |
| :--- | :--- | :--- | :--- |
| `TRANSPORT-ORIGIN` | Transport | Rejects requests with untrusted `Origin` headers (`403`) | MCP Security Best Practices |
| `AUTH-401-CHALLENGE` | Discovery | Returns `401` with `WWW-Authenticate` `resource_metadata` | RFC 9728 §5.1 |
| `AUTH-PRM-SCHEMA` | Discovery | Serves valid Protected Resource Metadata JSON | RFC 9728 §2 |
| `AUTH-PRM-RESOURCE` | Discovery | PRM `resource` matches canonical MCP server URL | MCP Auth Spec |
| `AUTH-AS-METADATA` | Discovery | AS advertises `code_challenge_methods_supported: ["S256"]` | RFC 8414 / OAuth 2.1 |
| `TOKEN-AUD-MISMATCH` | Security | Rejects valid JWT minted for a different `aud` (`401`) | RFC 8707 / OAuth 2.1 |
| `TOKEN-EXPIRED` | Security | Rejects expired JWTs (`401`) | RFC 7519 |
| `TOKEN-QUERY-STRING` | Security | Rejects tokens passed via `?access_token=` query param | OAuth 2.1 §5.1.2 |
| `TOKEN-INSUFFICIENT-SCOPE` | AuthZ | Returns `403` + `insufficient_scope` on privileged tool calls | RFC 6750 §3.1 |

---

## Local Development

```bash
# Clone the repository
git clone https://github.com<your-username>/mcp-auth-validator.git
cd mcp-auth-validator

# Install dependencies
npm install

# Run in development mode
npx tsx src/cli.ts check http://localhost:3000/mcp

# Build for distribution
npm run build
```

---

## Contributing

Contributions are welcome! If you notice a new edge case in the MCP Authorization Specification or want to add additional adversarial probes (such as Client ID Metadata Document checks or `RFC 9207` issuer mix-up tests), please open an issue or submit a pull request.

## License

MIT

