# Threat Model: CredTrace

A lightweight STRIDE walkthrough. This is the artifact I'd actually bring
to a design review, not a checkbox exercise — each row either has a real
mitigation with a file reference, or is honestly marked as accepted risk /
future work.

## System overview & trust boundaries

```
┌─────────────┐        HTTPS (TLS terminated        ┌──────────────────────┐
│   Browser    │◄──────  upstream, e.g. by a  ──────►│   FastAPI app         │
│ (untrusted)  │        load balancer / ingress)      │   (trust boundary A)  │
└─────────────┘                                       └──────────┬───────────┘
                                                                  │
                                                       SQL over local socket /
                                                       TCP (trust boundary B)
                                                                  │
                                                       ┌──────────▼───────────┐
                                                       │  Database             │
                                                       │  (credential metadata │
                                                       │   only -- no secrets) │
                                                       └────────────────────────┘
```

**Trust boundary A** (browser ↔ app): the browser is fully untrusted. Every
input is attacker-controlled until validated.

**Trust boundary B** (app ↔ database): the database is trusted *by* the
app but is a high-value target *of* an attacker who compromises the app —
this is why it holds metadata, not secrets: compromising boundary B still
doesn't hand out real credentials.

**Assets**: user session tokens, the credential-usage graph itself (this
*is* sensitive — it's a map of where an attacker should look next), the
audit log (integrity matters more than confidentiality here), user
password hashes.

**Explicitly not an asset of this system**: actual secret values. They
live in whatever the `vault_reference` points to (Vault, AWS Secrets
Manager, etc.), which is out of scope for this threat model and has its
own.

## STRIDE

### Spoofing

| Threat | Mitigation | Status |
|---|---|---|
| Attacker guesses/brute-forces a password | Argon2id hashing + rate-limited login + account lockout after 5 failures | Mitigated (`app/auth.py`) |
| Attacker enumerates valid usernames via login response differences | Identical error message + dummy-hash verify for unknown users, so timing doesn't leak existence | Mitigated (`app/auth.py::authenticate`) |
| Session fixation (attacker sets a victim's session token) | New random token minted server-side on every login; the app never accepts a client-supplied session identifier | Mitigated (`app/auth.py::create_session`) |
| Attacker steals a session cookie via XSS | HttpOnly cookie (unreadable from JS) + strict CSP blocking inline/external script | Mitigated, contingent on no XSS existing — see Tampering |
| No MFA, so a leaked password is fully sufficient | — | **Accepted risk / roadmap** — see SECURITY.md |

### Tampering

| Threat | Mitigation | Status |
|---|---|---|
| SQL injection via search/form fields | SQLAlchemy ORM exclusively, zero raw/string-formatted SQL anywhere in the codebase | Mitigated, verified with an injection-payload test (`tests/` search tests + manual `' OR 1=1 --` check during build) |
| Stored XSS via credential/project name or notes fields | Jinja2 autoescaping (on by default, never disabled) + CSP as defense in depth | Mitigated |
| CSRF: attacker's site submits a form on the victim's behalf | Synchronizer token bound to the server-side session, checked on every state-changing route | Mitigated (`app/deps.py::verify_csrf`), tested directly (`tests/test_csrf.py`) |
| Attacker tampers with a `vault_reference` to point elsewhere, redirecting whoever reads it toward an attacker-controlled path | Input validation restricts the field to pointer-shaped values, but doesn't verify the pointer actually resolves to what it claims | **Partially mitigated** — validation reduces the class of raw-secret-paste but doesn't prove pointer authenticity. Roadmap: allowlist expected vault-reference prefixes per deployment. |
| Open redirect via the `next=`/`redirect_to=` parameters used after login/mutations | Every such parameter is checked to start with `/` and not `//` before use | Mitigated (`app/routers/auth_routes.py`, `app/routers/mappings.py`) |

### Repudiation

| Threat | Mitigation | Status |
|---|---|---|
| A user denies having made a change | Every create/update/delete/login/logout is written to an append-only `AuditLog` with username, action, entity, timestamp, IP | Mitigated (`app/audit.py`) |
| An attacker with DB write access edits the audit log to cover their tracks | The audit log lives in the same database as everything else -- no independent write-once store | **Accepted risk / roadmap** — ship audit events to an external, append-only sink (SIEM) so DB compromise doesn't also erase the trail |

### Information Disclosure

| Threat | Mitigation | Status |
|---|---|---|
| The core dataset itself (which credential maps to which project) is disclosed to someone who shouldn't have it | RBAC gates every route; the app requires auth for literally everything except `/healthz` and `/login` | Mitigated |
| Verbose error messages / stack traces leak internals | `debug=False` by default; FastAPI's default exception handling doesn't echo tracebacks to the client when debug is off | Mitigated — **recommend verifying explicitly** with a forced 500 in a staging environment before go-live |
| API docs (`/docs`, OpenAPI schema) hand an attacker a full endpoint map | Disabled entirely when `ENVIRONMENT=production` | Mitigated (`app/main.py`) |
| Session cookie sent over plain HTTP | `Secure` flag enabled automatically whenever `ENVIRONMENT=production` | Mitigated, **contingent on the operator actually setting ENVIRONMENT=production** |
| Referrer leakage of internal URLs to third parties | `Referrer-Policy: no-referrer` | Mitigated (`app/middleware.py`) |
| Timing side-channel distinguishing valid vs invalid CSRF tokens | `hmac.compare_digest` for the comparison | Mitigated (`app/security.py::constant_time_eq`) |

### Denial of Service

| Threat | Mitigation | Status |
|---|---|---|
| Login endpoint hammered to lock out legitimate users or exhaust resources | Rate limiting (10/min/IP) *and* per-account lockout | Mitigated for single-instance deployments |
| Rate limiter storage is in-process memory | Fine for one replica; **breaks down across multiple replicas or a serverless platform** (each has its own counter — on Vercel, effectively every request can be a fresh counter) | **Accepted risk for now** — the DB-backed per-account lockout (see Spoofing, above) is what actually protects a Vercel/serverless deployment; move the rate limiter to Redis-backed storage before treating it as a real control there |
| Oversized form field values used to exhaust storage/memory | Every free-text Pydantic field has an explicit `max_length` | Mitigated (`app/schemas.py`) |
| Slow-loris / connection-exhaustion at the HTTP layer | Out of scope for the app itself — expected to be handled by the reverse proxy / load balancer in front of it | Explicitly delegated, documented here so it isn't silently assumed |
| Database connection exhaustion under concurrent serverless load (each function invocation opening its own Postgres connection) | `NullPool` + a runtime warning if `DATABASE_URL` doesn't look like it's using a transaction-mode pooler in production | Mitigated (`app/database.py`), verified against a real local Postgres instance while building this feature, not just assumed |

### Elevation of Privilege

| Threat | Mitigation | Status |
|---|---|---|
| A viewer account calls an editor/admin-only route directly | Every mutating route is gated by `require_role()`, independent of what the UI shows or hides | Mitigated, tested (`tests/test_rbac.py`) |
| Privilege escalation via mass-assignment (submitting an unexpected `role` field on a non-user-management form) | Pydantic schemas whitelist exactly which fields each endpoint accepts; there is no generic "update these fields" endpoint | Mitigated by construction |
| A compromised container escapes to the host | Non-root user, `cap_drop: ALL`, read-only root filesystem | Mitigated (`Dockerfile`, `docker-compose.yml`) — **standard pattern, not penetration-tested** |
| The last remaining active admin gets deactivated, leaving the app permanently unadministrable | `would_be_last_active_admin()` blocks it | Mitigated in code, but with a caveat worth being honest about: the acting admin is blocked from deactivating *themselves* separately, which means their own active session always keeps the count at ≥1 through the ordinary single-actor HTTP flow — so this specific guard is unreachable *through the UI* today. It's kept as defense-in-depth for a future bulk-deactivate feature and for a race between two admins' concurrent requests, and is tested directly at the function level rather than through the HTTP route (`tests/test_rbac.py`). **Found while writing this document, fixed, and then tested honestly rather than with a misleading integration test** — which is the actual point of threat modeling before shipping. |

## How to use this document

If you're extending this project: add a row before you add a feature, not
after. If a mitigation is "accepted risk," that's a real decision someone
should sign off on, not a place where the analysis just trails off.
