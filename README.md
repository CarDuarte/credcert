# CredTrace

A credential **usage tracker** — not a password manager. CredTrace never
stores secret values. It stores *metadata*: which credential exists, which
projects/services consume it, and where. Its core question is:

> "If I rotate this credential, what breaks?"

Every credential's detail page shows its **blast radius**: every project
that depends on it, ranked so production impact is impossible to miss.

## Why metadata-only is the security design

The single biggest decision in this project is that it **cannot** leak
actual secrets, because it never holds them. A `vault_reference` field
records *where* the real value lives (a Vault path, an AWS Secrets Manager
ARN) — never the value itself. Input validation actively rejects anything
pasted into that field that looks like it might be a raw secret rather than
a pointer (see `app/schemas.py::reject_looks_like_secret`). This removes an
entire class of risk: this database being a target worth breaching for
secret theft.

## Quick start (local dev)

`.env` is loaded automatically (via `python-dotenv`) by anything that
imports `app.config` — the app itself, `scripts/seed.py`, and Alembic. No
manual `export` step needed, on any OS. A real environment variable
already set (e.g. by Docker or Vercel) always wins over `.env`.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: at minimum set ADMIN_USERNAME / ADMIN_PASSWORD for the seed script

python scripts/seed.py                 # creates the first admin user, reads .env automatically

uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000`.

## Quick start (Docker)

```bash
cp .env.example .env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
docker compose up --build
```

> Docker itself wasn't available in the environment this project was
> generated in, so the Dockerfile/compose file are written to standard
> patterns and YAML-validated, but **not build-tested**. Run
> `docker compose build` yourself as a first check before relying on them.

## Deploying to Vercel + Supabase

CredTrace runs on Vercel's Python runtime with zero build configuration
beyond `pyproject.toml`'s `[tool.vercel]` entrypoint pointer (already set
up, since the app lives at `app/main.py` rather than a root-level file
Vercel would find by convention). What actually needs your attention is
the database, because a serverless platform changes some assumptions that
were free on a normal server:

**1. Create a Supabase project**, then grab two connection strings from
its Connect page:
- The **transaction-mode pooler** string (port `6543`) — this is what the
  running app uses.
- The **session-mode pooler or direct connection** string (port `5432`) —
  this is what migrations use. DDL doesn't play well with transaction-mode
  pooling, so trying to run `alembic upgrade head` through port 6543 will
  intermittently fail in confusing ways.

Why this split matters: serverless functions don't hold a database
connection open the way a normal server does — each invocation may be a
fresh process. Point the *app* at the direct port and you'll exhaust
Supabase's connection limit the moment you get real concurrent traffic.
This app already ships with the right defaults for the pooled path
(`NullPool` + disabled server-side prepared statements — see
`app/database.py` for why) so you don't need to configure that part, just
use the right connection string.

**2. Run migrations once**, from your machine or CI, against the direct/
session-mode string:

```bash
export MIGRATION_DATABASE_URL="postgresql://...:5432/postgres"   # session mode or direct
alembic upgrade head
```

**3. Seed the first admin user** the same way:

```bash
export DATABASE_URL="$MIGRATION_DATABASE_URL"
ADMIN_USERNAME=you ADMIN_PASSWORD='...' python scripts/seed.py
```

**4. In the Vercel project's environment variables**, set:

```
ENVIRONMENT=production
SECRET_KEY=<openssl rand -hex 32>
DATABASE_URL=postgresql://...:6543/postgres    # transaction-mode pooler
TRUSTED_HOSTS=your-app.vercel.app
```

**5. Push to a Git repo connected to the Vercel project.** Vercel detects
the FastAPI app from `requirements.txt` + the `pyproject.toml` entrypoint
automatically — no `vercel.json` build config needed beyond the
`maxDuration` bump already in this repo's `vercel.json`.

**What's different on Vercel vs. the Docker deployment, worth knowing
about rather than being surprised by:**

- **Login rate limiting is best-effort only.** `slowapi`'s rate limiter
  keeps its counters in process memory; on a serverless platform, a "fresh
  process" can happen on almost any request, so the counter doesn't
  reliably persist between attempts. The *real* protection against brute
  force is the per-account lockout in `app/auth.py`, which lives in
  Postgres and is therefore correctly enforced no matter how many function
  instances are running. If you want real distributed rate limiting on
  Vercel, swap `slowapi`'s in-memory storage for a Redis-backed one (e.g.
  Upstash, which has an official Python client built for exactly this) —
  not done here since it's an extra piece of infrastructure to provision,
  not a code complexity issue.
- **No local filesystem.** The app doesn't write anything to disk besides
  the (now unused, on Vercel) SQLite file, so this doesn't affect
  CredTrace specifically — just don't add a feature that assumes one
  without checking this section first.

## Running the test suite

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app --cov-report=term-missing
```

31 tests, ~80% coverage, covering auth, CSRF, RBAC, the blast-radius
mapping logic, and security headers. The suite runs against SQLite by
default; CI also runs it against a real Postgres service container
(`test-postgres` in `.github/workflows/ci.yml`), and that path — Alembic
migration, psycopg v3 driver, full auth→CSRF→blast-radius flow — was
additionally verified by hand against a real local Postgres instance
while building this feature, not just assumed to work because SQLite did.

## Running the security tooling locally

```bash
pip install -r requirements-dev.txt
ruff check app/ scripts/ tests/     # lint
bandit -r app/ scripts/ -c pyproject.toml   # SAST
pip-audit -r requirements.txt       # known CVEs in dependencies
```

All three are wired into `.github/workflows/ci.yml` and run on every push
and PR — see [SECURITY.md](SECURITY.md) for the full pipeline.

## Architecture

```
Browser
  │  (session cookie: HttpOnly, Secure in prod, SameSite=Lax)
  ▼
FastAPI app (server-rendered Jinja2, no separate frontend/API split)
  │
  ├── app/routers/        one router per resource (auth, credentials,
  │                       projects, mappings, users, audit)
  ├── app/deps.py          RBAC + CSRF as FastAPI dependencies
  ├── app/auth.py          login, session lifecycle, lockout
  ├── app/security.py      password hashing, tokens, timing-safe compares
  ├── app/models.py        SQLAlchemy ORM (credentials are metadata-only)
  ├── app/middleware.py     security headers, HTTPS redirect
  └── app/templates/        Jinja2, CSP-safe (no inline script/style)
```

A deliberate architectural choice: **server-rendered HTML, not a JSON API +
SPA**. This removes an entire category of risk (no CORS surface, no token-
in-JavaScript exposure) and keeps the CSRF story simple (synchronizer
token, not a bearer token that has to be stored somewhere in the browser).

## Data model

- **Credential** — metadata only: name, owner, criticality, rotation
  schedule, and a `vault_reference` pointer. No secret values, ever.
- **Project** — a system/service that consumes credentials.
- **CredentialUsage** — the mapping between the two: "this credential is
  used *here*, like *this*." This table is the actual value of the tool.
- **User / UserSession** — server-side sessions (instantly revocable,
  unlike stateless JWTs).
- **AuditLog** — append-only record of who did what.

## Roles

| Role   | Can do |
|--------|--------|
| viewer | Read everything |
| editor | + create/edit/delete credentials, projects, mappings |
| admin  | + manage users, view the audit log |

## What's genuinely finished vs. what's a starting point

Finished and tested: auth, session management, CSRF, RBAC, input
validation, the blast-radius view, audit logging, the CI pipeline
definitions, and the Postgres/Supabase deployment path (migrations, URL
normalization, pooler-safe connection settings) — the last of these was
verified against a real local Postgres instance, not just SQLite.

Deliberately left as follow-up work (see the "Where to take this next"
section of [SECURITY.md](SECURITY.md)): the Docker build is untested in
this environment (Docker wasn't available in the environment this project
was generated in), and likewise the Vercel deploy itself is untested end
-to-end (no Vercel/Supabase account available in this environment) — the
SQLAlchemy/Alembic/psycopg side of that path *is* verified for real, but
"Vercel actually builds and serves this" is a claim you should confirm
yourself as the first step, the same way you should for Docker.

## Database migrations

Alembic is fully wired up (`alembic/env.py` reads `DATABASE_URL` from the
same app config as everything else — no separate hardcoded connection
string to keep in sync). In development, `create_all()` runs automatically
on startup for convenience. **In production, run migrations explicitly
instead:**

```bash
alembic upgrade head
```

To generate a new migration after changing `app/models.py`:

```bash
alembic revision --autogenerate -m "describe the change"
# then read the generated file before committing it -- autogenerate is a
# draft, not a guarantee
```
