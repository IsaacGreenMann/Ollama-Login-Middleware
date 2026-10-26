# Ollama IAM Gateway

This project is an identity and access management gateway for a local [Ollama](https://ollama.com) server. It is the Part 4 extension for CS411: a Python service that sits in front of Ollama, signs users in, and only then forwards API calls. Ollama itself is not modified. After a user is authenticated, a small per-user rate limiter applies a quota so the gateway can hand a stable user identity to a fuller rate-limiting or backpressure extension.

## Architecture

Browsers and API clients talk to this gateway (port 8080). The gateway stores accounts in SQLite, checks passwords with bcrypt, and issues a signed JWT. The browser keeps that token in an HTTP-only cookie. Scripts can send the same token as `Authorization: Bearer <token>`.

A request to `/api/*` then walks a fixed pipeline:

1. **Authenticate.** The JWT is verified and the account is loaded from the database. The role inside the token is not trusted, so a demotion applies on the next call.
2. **Authorize.** Every signed-in role may call chat, generate, and the other ordinary Ollama routes. `POST /api/pull`, `/api/delete`, `/api/push`, and `/api/copy` require the `admin` role.
3. **Rate limit.** An in-memory sliding window allows 30 requests per 60 seconds for that user (both numbers are configurable). Over the limit, the gateway returns `429` and `Retry-After` without contacting Ollama.
4. **Proxy.** The call is streamed to Ollama at `http://127.0.0.1:11434`. Generate and chat responses are newline-delimited JSON and are forwarded chunk by chunk.

```
Browser or API client
        |
        v
Ollama IAM Gateway :8080
  authenticate -> authorize -> rate limit -> proxy
        |
        v
Ollama :11434
```

Pages (`/login`, `/register`, `/`, `/admin`) are Jinja templates served by the same FastAPI app. They are not proxied to Ollama.

The in-memory limiter is intentionally small. It exists to show the integration point: the quota key is the authenticated user id. Replacing `SlidingWindowRateLimiter` does not require a change to login or to the proxy.

## Prerequisites

- Python 3.10 or newer
- Ollama installed locally and running (`ollama serve`, which listens on port 11434)

The gateway still starts if Ollama is down. API calls then return `502` until Ollama is available. Login and the admin dashboard do not need Ollama.

## Installation

From the `ollama-iam` directory:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS or Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## How to run

Still inside `ollama-iam`, with the virtual environment active and Ollama already serving:

```bash
uvicorn main:app --reload --port 8080
```

Open [http://127.0.0.1:8080/login](http://127.0.0.1:8080/login). Interactive API docs are at [http://127.0.0.1:8080/docs](http://127.0.0.1:8080/docs).

On the first launch, if `iam.db` has no users, the process creates the default administrator and prints the username and password. It also writes a JWT signing key to `.jwt_secret` when `JWT_SECRET` is not set. Both files are local and are listed in `.gitignore`.

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `JWT_SECRET` | contents of `.jwt_secret` | HMAC secret for access tokens. Use at least 32 characters if you set it yourself |
| `JWT_EXPIRE_HOURS` | `24` | Token and cookie lifetime |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Upstream Ollama API |
| `DATABASE_PATH` | `iam.db` in this directory | SQLite file |
| `RATE_LIMIT_REQUESTS` | `30` | Requests allowed per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding window length |
| `COOKIE_SECURE` | `false` | Set `true` only behind HTTPS |

PowerShell example:

```powershell
$env:JWT_SECRET = "replace-me"
$env:RATE_LIMIT_REQUESTS = "30"
uvicorn main:app --reload --port 8080
```

## Default credentials

When the database is empty at startup the gateway inserts:

- username: `admin`
- password: `admin`

That password is for a local demo. Registration creates accounts with the `user` role only. Promote another administrator from the dashboard before deleting the original admin. The signed-in admin cannot delete or demote their own account, and the last remaining admin cannot be removed.

## API endpoints

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/login` | No | Login page |
| `GET` | `/register` | No | Registration page |
| `POST` | `/register` | No | Create a `user` account, set the cookie, and return a JWT |
| `POST` | `/login` | No | Check the password, set the cookie, and return a JWT |
| `POST` | `/logout` | No | Clear the cookie |
| `GET` | `/me` | Yes | Current username, role, and id |
| `GET` | `/` | Yes | Home page |
| `GET` | `/admin` | Admin | Dashboard page. Other roles get the 403 page |
| `GET` | `/admin/users` | Admin | JSON list of accounts |
| `PUT` | `/admin/users/{id}/role` | Admin | Body `{"role": "admin"}` or `{"role": "user"}` |
| `DELETE` | `/admin/users/{id}` | Admin | Delete an account |
| `*` | `/api/*` | Yes | Proxied to Ollama. Pull, delete, push, and copy require admin |

Login and register return JSON of the form:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {"id": 1, "username": "admin", "role": "admin", "created_at": "2026-10-25 00:00:00"}
}
```

The same token is set as the `access_token` cookie (`HttpOnly`, `SameSite=Lax`).

Common status codes: `401` missing or bad token, `403` role denied, `409` username taken, `422` invalid form body, `429` quota exceeded (`Retry-After` is set), `502` Ollama is not running, `504` Ollama timed out. Successful proxied responses also include `X-RateLimit-Limit` and `X-RateLimit-Remaining`.

Example calls from PowerShell. `curl.exe` is Windows' curl, not the `Invoke-WebRequest` alias:

```powershell
curl.exe -s -X POST http://127.0.0.1:8080/login -H "Content-Type: application/json" -d '{"username":"admin","password":"admin"}'

curl.exe -s http://127.0.0.1:8080/api/tags -H "Authorization: Bearer TOKEN"

curl.exe -N -X POST http://127.0.0.1:8080/api/generate -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d '{"model":"llama3.2","prompt":"Hello","stream":true}'
```

`-N` disables curl's buffer so a streaming generate response prints as Ollama produces it.

## Project layout

```
ollama-iam/
├── main.py                 # App startup, static files, middleware
├── config.py               # Environment-backed settings
├── database.py             # SQLite user table and queries
├── auth.py                 # bcrypt, JWT, current-user dependency
├── rate_limiter.py         # Per-user sliding window
├── middleware.py           # Authenticate, authorize, rate limit /api/*
├── routes/
│   ├── auth_routes.py      # Login, register, logout, /me, home
│   ├── admin_routes.py     # Dashboard and user administration
│   └── proxy_routes.py     # Streaming reverse proxy
├── templates/              # Login, register, home, admin, 403
└── static/style.css
```

## Screenshots

Placeholder: add captures of the login page, the registration page, the home page, and the admin dashboard here.

<!--
![Login](screenshots/login.png)
![Register](screenshots/register.png)
![Home](screenshots/home.png)
![Admin dashboard](screenshots/admin.png)
-->

## Limitations

- Quotas live in process memory, so they reset on restart and are not shared across multiple gateway processes.
- Login attempts are not rate limited. The quota starts after a token is accepted.
- Registration is open and always creates a `user`. There is no email verification or password-change form.
- The cookie is not marked `Secure` unless `COOKIE_SECURE=true`, because the demo is plain HTTP on localhost.
