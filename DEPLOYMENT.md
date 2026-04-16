# Deployment Guide (Production)

This project deploys as two services:

1. `frontend` (Next.js) at repo root.
2. `backend` (FastAPI GitHub App) in `github-app/`.

## 1) Deploy backend first

Recommended host: Railway.

- Root directory: `github-app`
- Start command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Set backend environment variables:

- `GITHUB_APP_ID`
- `GITHUB_PRIVATE_KEY` (inline PEM with `\n` escapes, or absolute file path)
- `GITHUB_WEBHOOK_SECRET`
- `GEMINI_API_KEY`
- `GEMINI_MODEL` (for example `gemini-2.5-flash`)
- `API_SECRET` (long random string)
- `DATABASE_URL`
  - SQLite (simple): `sqlite:///./scans.db`
  - PostgreSQL (recommended): `postgresql+psycopg://USER:PASS@HOST/DB`

Smoke test:

- `GET /health` returns `{"status":"ok"}`

## 2) Configure GitHub App

In your GitHub App settings:

- Webhook URL: `https://<your-backend-domain>/webhook`
- Webhook secret: same as `GITHUB_WEBHOOK_SECRET`
- Subscribe to event: `Pull requests`

Repository permissions:

- Pull requests: **Read & write**
- Contents: **Read & write**
- Commit statuses: **Read & write**
- Workflows: **Read & write** (recommended if auto-fixes may touch workflow files)

Install the GitHub App on target repositories.

## 3) Deploy frontend

Recommended host: Vercel (repo root).

Set frontend environment variables:

- `GITHUB_ID`
- `GITHUB_SECRET`
- `NEXTAUTH_SECRET`
- `NEXTAUTH_URL=https://<your-frontend-domain>`
- `BACKEND_URL=https://<your-backend-domain>`
- `API_SECRET` (must exactly match backend `API_SECRET`)
- `NEXT_PUBLIC_GITHUB_APP_INSTALL_URL=https://github.com/apps/<your-app-slug>/installations/new` (optional but recommended)

## 4) Configure GitHub OAuth App (for login)

Set OAuth callback URL:

`https://<your-frontend-domain>/api/auth/callback/github`

## 5) Post-deploy checks

1. Login works at `/login`.
2. Dashboard loads scans only for the logged-in GitHub owner.
3. Opening a PR in an installed repo triggers a scan.
4. Scan status updates automatically in dashboard pages.
5. Suggested fix can be applied and creates a commit on PR branch.

## Security checklist

- Use strong random values for `NEXTAUTH_SECRET` and `API_SECRET`.
- Never commit `.env`, `.env.local`, or private keys.
- Restrict GitHub App installation scope to only required repositories.
- Prefer PostgreSQL for production durability.
