# Ollama IAM Gateway

> CS411 Software Architecture Design — Project #1, Part 4  
> Bilkent University, 2026–2027 Fall

An identity and access management (IAM) reverse-proxy gateway for [Ollama](https://ollama.com). The gateway sits in front of a local Ollama server, authenticates users via JWT, enforces role-based access control, and applies per-user rate limiting — then forwards admitted requests to Ollama. Ollama itself is never modified.

## Architecture Overview

```
Browser / CLI / API Client
            │
            ▼
  ┌─────────────────────────┐
  │  IAM Gateway  :8080     │
  │                         │
  │  1. Authenticate (JWT)  │──── 401 Unauthenticated
  │  2. Authorize  (RBAC)   │──── 403 Forbidden
  │  3. Rate Limit (per-user)│──── 429 Too Many Requests
  │  4. Proxy (stream)      │
  └────────────┬────────────┘
               ▼
       Ollama Server  :11434
               │
      Scheduler → Runner → Inference Engine
```

The gateway intercepts every `/api/*` request and runs a three-stage security pipeline before forwarding it to Ollama:

1. **Authentication** — Extracts the JWT from the `Authorization: Bearer` header or from the HTTP-only cookie. Verifies the signature (HMAC-SHA256), checks expiration, and reloads the user's current role from the database on every request.
2. **Authorization** — Chat and generate endpoints are open to all authenticated users. Model management operations (pull, delete, push, copy) require the `admin` role.
3. **Rate Limiting** — An in-memory sliding-window limiter enforces a per-user quota (default: 30 requests / 60 seconds). Over the limit, the gateway returns HTTP 429 with a `Retry-After` header without contacting Ollama.

Admitted requests are streamed to Ollama using an async HTTP client (httpx). Responses from `/api/generate` and `/api/chat` are newline-delimited JSON and are forwarded chunk-by-chunk — the gateway never buffers the full response.

Web pages (`/login`, `/register`, `/`, `/admin`) are Jinja2 templates served by the same FastAPI process. They are not proxied to Ollama.

## Prerequisites

- **Python 3.10** or newer
- **Ollama** installed and running locally (`ollama serve` on port 11434)

> The gateway starts even if Ollama is down. Login, registration, and the admin dashboard work independently. API calls return `502 Bad Gateway` until Ollama is available.

## Installation

```bash
cd ollama-iam
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## How to Run

With the virtual environment active and Ollama serving:

```bash
uvicorn main:app --reload --port 8080
```

Open **http://127.0.0.1:8080/login** in a browser. Interactive API docs: **http://127.0.0.1:8080/docs**.

On first launch, if the database is empty, the gateway:
- Creates a default administrator account and prints the credentials to the console.
- Generates a JWT signing key and saves it to `.jwt_secret`.

### Default Credentials

| Username | Password | Role  |
|----------|----------|-------|
| `admin`  | `admin`  | admin |

New accounts created via `/register` are assigned the `user` role. An admin can promote other users from the dashboard. The signed-in admin cannot delete or demote their own account, and the last remaining admin cannot be removed.

## Configuration

All settings are optional and have working defaults for local development.

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | auto-generated in `.jwt_secret` | HMAC signing key for tokens (use ≥32 characters if you set it yourself) |
| `JWT_EXPIRE_HOURS` | `24` | Token and cookie lifetime |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Upstream Ollama address |
| `DATABASE_PATH` | `iam.db` (project directory) | SQLite database file |
| `RATE_LIMIT_REQUESTS` | `30` | Max requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window duration |
| `COOKIE_SECURE` | `false` | Set `true` when behind HTTPS |

## API Endpoints

### Public (no authentication)

| Method | Path | Description |
|---|---|---|
| `GET` | `/login` | Login page |
| `GET` | `/register` | Registration page |
| `POST` | `/login` | Authenticate and receive a JWT |
| `POST` | `/register` | Create account and receive a JWT |
| `POST` | `/logout` | Clear the authentication cookie |

### Authenticated (valid JWT required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Home page (shows user info) |
| `GET` | `/me` | Current user as JSON |
| `*` | `/api/*` | Proxied to Ollama |

### Admin only

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin` | User management dashboard |
| `GET` | `/admin/users` | JSON list of all accounts |
| `PUT` | `/admin/users/{id}/role` | Change role: `{"role": "admin"}` or `{"role": "user"}` |
| `DELETE` | `/admin/users/{id}` | Delete an account |

### Ollama proxy (admin-restricted operations)

| Endpoint | All users | Admin only |
|---|---|---|
| `/api/chat`, `/api/generate` | ✓ | ✓ |
| `/api/tags`, `/api/show` | ✓ | ✓ |
| `/api/pull`, `/api/push` | ✗ | ✓ |
| `/api/delete`, `/api/copy` | ✗ | ✓ |

### Response format

Login and register return:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "created_at": "2026-10-25 00:00:00"
  }
}
```

The same token is set as the `access_token` cookie (`HttpOnly`, `SameSite=Lax`).

Status codes: `401` invalid/missing token · `403` insufficient role · `409` username taken · `422` invalid body · `429` rate limit exceeded (includes `Retry-After`) · `502` Ollama unreachable · `504` Ollama timeout.

Proxied responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers.

## Demo Walkthrough

On Windows PowerShell, use `curl.exe` so the shell does not call `Invoke-WebRequest`.

**1. Login**

```bash
curl.exe -s -X POST http://127.0.0.1:8080/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin\"}"
```

Save the returned `access_token` as `TOKEN`.

**2. List models (authenticated)**

```bash
curl.exe -s http://127.0.0.1:8080/api/tags \
  -H "Authorization: Bearer TOKEN"
```

**3. Chat with a model**

```bash
curl.exe -N -X POST http://127.0.0.1:8080/api/chat \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"llama3.2\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}"
```

**4. Rejected without a token**

```bash
curl.exe -s http://127.0.0.1:8080/api/tags
# → 401 {"detail": "Authentication required."}
```

**5. Rate limit exceeded**

Send 31 rapid requests and the 31st returns:

```
HTTP 429 {"detail": "Rate limit exceeded for this user."}
Retry-After: <seconds>
```

## Project Structure

```
ollama-iam/
├── main.py                 # App entry point, lifespan, middleware registration
├── config.py               # Environment-backed settings with defaults
├── database.py             # SQLite schema and user CRUD operations
├── auth.py                 # bcrypt hashing, JWT sign/verify, FastAPI auth dependencies
├── rate_limiter.py         # In-memory per-user sliding-window rate limiter
├── middleware.py            # ASGI middleware: auth → authz → rate limit on /api/*
├── requirements.txt        # pip dependencies
│
├── routes/
│   ├── __init__.py
│   ├── auth_routes.py      # /login, /register, /logout, /me, /
│   ├── admin_routes.py     # /admin dashboard and user management API
│   └── proxy_routes.py     # Streaming reverse proxy to Ollama
│
├── templates/
│   ├── base.html           # Shared HTML layout
│   ├── login.html          # Login form
│   ├── register.html       # Registration form
│   ├── home.html           # Post-login landing page
│   ├── admin.html          # Admin user management table
│   └── forbidden.html      # 403 error page
│
├── static/
│   └── style.css           # Dark-themed UI stylesheet
│
├── screenshots/            # UI captures for the report
├── .jwt_secret             # Auto-generated signing key (gitignored)
├── iam.db                  # SQLite database (gitignored, created at runtime)
└── .gitignore
```

## Security Measures

- **Passwords** are hashed with bcrypt before storage. Plaintext is never written to the database.
- **Timing-attack resistance** — Failed logins for nonexistent usernames still run a bcrypt comparison against a dummy hash, so response time does not reveal whether an account exists.
- **JWT algorithm pinned to HS256** — The accepted algorithm list is explicit, blocking `alg=none` signature-bypass attacks.
- **Signing key not hardcoded** — Generated once with `secrets.token_urlsafe(48)` and saved to `.jwt_secret`. Overridable via the `JWT_SECRET` environment variable.
- **HTTP-only cookies** — The browser cannot read the token via JavaScript, mitigating XSS-based token theft.
- **Role reloaded from database** — The role stored in the JWT is not trusted for authorization. The user's current role is read from SQLite on every request, so a demotion takes effect immediately.

## Integration with Part 3

The IAM module and the rate-limiting extension (Part 3) are designed to compose:

| Concern | Part 4 (IAM) | Part 3 (Rate Limiting) |
|---|---|---|
| Question it answers | *Who is making this request?* | *How much capacity may they consume?* |
| Mechanism | JWT authentication + RBAC | Sliding-window admission control |
| Key insight | Provides a verified user identity | Uses that identity for per-user quotas |

Without authentication, the rate limiter would fall back to IP-based identification, which is coarse (users behind the same NAT share a quota) and easy to bypass. With authentication, each account has its own independent quota. The `SlidingWindowRateLimiter` class can be replaced by a more advanced backpressure system without changing the authentication or proxy layers.

## Screenshots

![Login](screenshots/login.png)

![Register](screenshots/register.png)

![Home](screenshots/home.png)

![Admin dashboard](screenshots/admin.png)

![Forbidden for non-admin](screenshots/forbidden.png)

## Limitations

- Quotas live in process memory, so they reset on restart and are not shared across multiple gateway processes.
- Login attempts are not rate limited. The quota starts after a token is accepted.
- Registration is open and always creates a `user`. There is no email verification or password-change form.
- The cookie is not marked `Secure` unless `COOKIE_SECURE=true`, because the demo is plain HTTP on localhost.
