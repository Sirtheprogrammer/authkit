# AuthKit

> **The open-source, stateless authentication and user management kit ready for any project.**  
> Built in Go for single-binary portability, ultra-low memory footprint, and instant verification across microservices.

[![Go Version](https://img.shields.io/badge/go-1.26-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-white.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Stateless](https://img.shields.io/badge/stateless-JWKS%20RFC%207517-white.svg)]()
[![Multi-DB](https://img.shields.io/badge/databases-SQLite%20|%20Postgres%20|%20MySQL%20|%20Mongo-lightgrey.svg)]()
[![AI Ready](https://img.shields.io/badge/AI-Model%20Context%20Protocol%20(MCP)-black.svg)]()

---

## Overview

AuthKit is a complete, self-contained authentication and user management microservice that you can set up on your machine or server with a **single command**.

Unlike traditional auth solutions that require downstream services to query a database on every request, AuthKit operates **completely statelessly** using cryptographic JWTs and an RFC 7517 **JWKS endpoint** (`/.well-known/jwks.json`). Client applications (Next.js, React, Flutter, Python, Go, Node) verify tokens in microseconds without touching AuthKit's database.

```mermaid
flowchart LR
    Client["Client / Frontend<br/>Web, Mobile"] -->|"1. Login / Signup"| AuthKit["AuthKit Service<br/>Port 8080"]
    AuthKit -->|"2. Asymmetric Stateless JWT"| Client
    Client -->|"3. Bearer Token"| Microservice["Downstream Microservices<br/>Node, Python, Go"]
    Microservice -->|"4. Verify via Cached JWKS"| AuthKitJWKS["AuthKit JWKS Endpoint<br/>/.well-known/jwks.json"]

    subgraph StorageEngines ["Storage Engines"]
        AuthKit -.-> SQLite["SQLite (Default)"]
        AuthKit -.-> Postgres["PostgreSQL"]
        AuthKit -.-> MySQL["MySQL"]
        AuthKit -.-> MongoDB["MongoDB"]
    end
```

---

## Key Features

- **100% Stateless & JWKS Ready:** Issues RS256/HS256 tokens with standard OpenID discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`).
- **Multi-Database Freedom:** Switch seamlessly between **SQLite** (pure Go zero-config default), **PostgreSQL**, **MySQL**, and **MongoDB**. Automatic migrations run on startup.
- **Fully Dynamic Custom Schema:** Store any custom metadata (phone numbers, organization, subscription tiers, addresses, preferences) with strict or permissive schema validation.
- **Google, Firebase & GitHub OAuth:**
  - Google Cloud OAuth2 / OpenID Connect
  - GitHub OAuth with private email resolution
  - Direct **Firebase Auth integration**: verifies Firebase client ID tokens and auto-provisions or federates users
- **Bring-Your-Own Email & Resend SDK:**
  - Standard SMTP (STARTTLS / TLS)
  - Resend API integration
  - Monochromatic responsive HTML email templates for 6-digit OTP verification and password reset
- **Model Context Protocol (MCP) AI Server:**
  - Built-in MCP JSON-RPC 2.0 server over **stdio** (`authkit mcp`) and **HTTP** (`POST /mcp`)
  - Enables Claude Desktop, Cursor, and autonomous AI agents to manage users, inspect tokens, and query authentication state
- **Monochromatic Landing Page, Docs & Admin Console:**
  - Embedded directly inside the binary via Go `embed.FS`
  - Zero external CDN or Node.js runtime required
  - Interactive API playground to test signup, login, and token decoding live in the browser
- **One-Command Setup:** Interactive CLI wizard (`authkit init`), Docker container, or 1-line curl script.

---

## Quickstart

### 1. One-Line Install Script
```bash
curl -fsSL https://raw.githubusercontent.com/sirtheprogrammer/authkit/main/scripts/install.sh | bash
```

### 2. Docker & Docker Compose
```bash
# Launch with embedded SQLite
docker run -d -p 8080:8080 -v authkit_data:/data authkit/authkit:latest

# Or launch with docker compose
docker compose up -d
```

### 3. Build & Run from Source
```bash
git clone https://github.com/sirtheprogrammer/authkit.git
cd authkit

# Run interactive setup wizard
go run ./cmd/authkit init

# Start service
go run ./cmd/authkit serve
```

Open **`http://localhost:8080`** in your browser to view the monochromatic landing page, interactive sandbox, documentation, and admin console!

---

## Database Setup

AuthKit selects the database driver automatically from `DB_TYPE` or `DATABASE_URL`:

### SQLite (Default)
```bash
export DB_TYPE=sqlite
export DB_FILE=./authkit.db
```

### PostgreSQL
```bash
export DB_TYPE=postgres
export DATABASE_URL="postgres://user:password@localhost:5432/authkit?sslmode=disable"
```

### MySQL
```bash
export DB_TYPE=mysql
export DATABASE_URL="root:password@tcp(localhost:3306)/authkit?parseTime=true"
```

### MongoDB
```bash
export DB_TYPE=mongodb
export DATABASE_URL="mongodb://localhost:27017/authkit"
```

---

## Dynamic Custom Schema

Define custom user fields in `authkit.yaml` without writing SQL migrations:

```yaml
schema:
  strict: false # if true, disallows fields not declared below
  fields:
    - name: phone
      type: string
      pattern: '^\+?[1-9]\d{1,14}$'
      required: false
    - name: company
      type: string
      max_length: 100
      required: true
    - name: tier
      type: string
      allowed_values: ["free", "pro", "enterprise"]
      default: "free"
```

---

## OAuth & Firebase Configuration

Set your provider credentials in `.env` or `authkit.yaml`:

```bash
# Google Cloud Console
GOOGLE_CLIENT_ID="xxx.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="xxx"
GOOGLE_REDIRECT_URL="http://localhost:8080/api/v1/auth/oauth/google/callback"

# GitHub Developer
GITHUB_CLIENT_ID="xxx"
GITHUB_CLIENT_SECRET="xxx"
GITHUB_REDIRECT_URL="http://localhost:8080/api/v1/auth/oauth/github/callback"

# Firebase Auth Project
FIREBASE_PROJECT_ID="my-firebase-project-id"
```

---

## Email Notifications (SMTP & Resend)

### SMTP
```bash
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME="you@gmail.com"
SMTP_PASSWORD="app-specific-password"
EMAIL_FROM="auth@yourdomain.com"
EMAIL_FROM_NAME="AuthKit"
```

### Resend SDK
```bash
EMAIL_PROVIDER=resend
RESEND_API_KEY="re_123456789abcdef"
EMAIL_FROM="auth@yourdomain.com"
EMAIL_FROM_NAME="AuthKit"
```

---

## Model Context Protocol (MCP) Setup

AuthKit provides native AI integration for AI assistants. To configure Claude Desktop:

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%/Claude/claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "authkit": {
      "command": "/usr/local/bin/authkit",
      "args": ["mcp"]
    }
  }
}
```

### Available MCP Tools
| Tool | Description |
| :--- | :--- |
| `authkit_list_users` | List and search users with role and status filters |
| `authkit_get_user` | Retrieve user profile, verification status, and dynamic metadata |
| `authkit_create_user` | Provision a new user with custom attributes |
| `authkit_update_user` | Update roles, metadata, or status |
| `authkit_ban_user` | Suspend or reactivate user and invalidate active sessions |
| `authkit_delete_user` | Permanently delete a user account |
| `authkit_inspect_token` | Statelessly decode and verify an AuthKit JWT token |
| `authkit_send_password_reset` | Dispatch password reset email |
| `authkit_get_system_stats` | Return system health, total user count, and storage engine |

---

## Stateless Verification Code Examples

### TypeScript / Next.js
```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('http://localhost:8080/.well-known/jwks.json'));

export async function verifyToken(token: string) {
  const { payload } = await jwtVerify(token, JWKS, { issuer: 'authkit' });
  return {
    userId: payload.sub,
    email: payload.email,
    role: payload.role,
    metadata: payload.metadata, // Custom dynamic schema attributes
  };
}
```

### Python / FastAPI
```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("http://localhost:8080/.well-known/jwks.json")

def verify_token(token: str):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience="authkit-api",
        issuer="authkit"
    )
```

---

## REST API Reference

### Auth Endpoints
- `POST /api/v1/auth/signup` — Create user and receive stateless token
- `POST /api/v1/auth/login` — Sign in with email and password
- `POST /api/v1/auth/refresh` — Rotate refresh token
- `POST /api/v1/auth/logout` — Invalidate session
- `GET  /api/v1/auth/me` — Get current user (Bearer token)
- `PUT  /api/v1/auth/me` — Update custom metadata
- `POST /api/v1/auth/password/forgot` — Request password reset
- `POST /api/v1/auth/password/reset` — Reset password with token/OTP
- `POST /api/v1/auth/verify-email/confirm` — Confirm email verification
- `POST /api/v1/auth/verify-email/resend` — Resend verification email
- `GET  /api/v1/auth/oauth/providers` — List configured OAuth providers
- `GET  /api/v1/auth/oauth/:provider` — Initiate OAuth redirect
- `GET  /api/v1/auth/oauth/:provider/callback` — OAuth callback
- `POST /api/v1/auth/firebase/verify` — Verify Firebase ID token

### Admin & System Endpoints
- `GET    /api/v1/users` — List users (Admin)
- `POST   /api/v1/users` — Create user (Admin)
- `GET    /api/v1/users/:id` — Get user (Admin)
- `PUT    /api/v1/users/:id` — Update user (Admin)
- `DELETE /api/v1/users/:id` — Delete user (Admin)
- `GET    /.well-known/jwks.json` — RFC 7517 Public Key Set
- `GET    /.well-known/openid-configuration` — RFC 8414 OIDC Discovery
- `GET    /health` — Operational health check
- `POST   /mcp` — Model Context Protocol JSON-RPC 2.0 endpoint

---

## CLI Commands

```bash
authkit serve             # Start HTTP server and embedded web console (default)
authkit init              # Interactive setup wizard to configure .env and authkit.yaml
authkit migrate           # Run database migrations manually
authkit admin create      # Provision a superadmin user (email password)
authkit token generate    # Generate test stateless JWT token
authkit mcp               # Run the Model Context Protocol (MCP) server over stdio
authkit version           # Show version information
```

---

## License

MIT &copy; 2026 AuthKit Authors. Free for personal and commercial use.
