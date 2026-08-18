# Security

## Reporting a vulnerability

This is a portfolio/learning project, not a production service handling
real user data. If you're reviewing it as part of a hiring process and
spot something, that's the point — open an issue or mention it directly.
If you fork this for real use, put a real disclosure process here (a
security@ address or a private GitHub Security Advisory) before you do.

## Design principle: it can't leak what it doesn't hold

The most important control in this codebase isn't a header or a library —
it's that **credential values are never stored**. `app/schemas.py` actively
rejects anything pasted into `vault_reference` that looks like a raw secret
rather than a pointer. Everything downstream (encryption at rest, backup
handling, breach blast-radius) is simpler because of this one decision.

## Controls implemented, mapped to OWASP ASVS / Top 10

| Control | Where | OWASP reference |
|---|---|---|
| Argon2id password hashing | `app/security.py` | ASVS 2.4 (credential storage) |
| Server-side, revocable sessions | `app/models.py::UserSession`, `app/auth.py` | ASVS 3 (session management) |
| Session idle + absolute timeout | `app/auth.py::get_valid_session` | ASVS 3.3 |
| CSRF synchronizer token, bound to session | `app/deps.py::verify_csrf` | A01:2021 (Broken Access Control) / ASVS 4.2 |
| RBAC (viewer/editor/admin) on every write route | `app/deps.py::require_role` | A01:2021 |
| Strict Pydantic validation on every write path | `app/schemas.py` | A03:2021 (Injection) / ASVS 5 |
| Parameterized queries only (SQLAlchemy ORM, no raw SQL) | throughout `app/routers/` | A03:2021 |
| Account lockout after repeated failed logins | `app/auth.py::authenticate` | A07:2021 (Auth Failures) |
| Rate-limited login endpoint | `app/routers/auth_routes.py` (slowapi) | A07:2021 |
| Timing-safe credential/CSRF comparison, dummy-hash on unknown username | `app/security.py`, `app/auth.py` | A07:2021 (username enumeration) |
| CSP with no `unsafe-inline`, HSTS, X-Frame-Options, etc. | `app/middleware.py` | A05:2021 (Security Misconfiguration) |
| `Secure` + `HttpOnly` + `SameSite=Lax` session cookie | `app/routers/auth_routes.py` | ASVS 3.4 |
| Least-privilege container (non-root, `cap_drop: ALL`, read-only rootfs) | `Dockerfile`, `docker-compose.yml` | A05:2021 |
| Serverless-safe DB pooling (`NullPool`, disabled server-side prepared statements) for Vercel/Supabase deployments | `app/database.py` | A05:2021 (Security Misconfiguration -- connection exhaustion under real traffic is a self-inflicted DoS) |
| Append-only audit log, never containing secrets/tokens | `app/audit.py` | ASVS 7 (logging) |
| Pinned dependencies + automated CVE scanning | `requirements.txt`, CI `dependency-audit` job | A06:2021 (Vulnerable Components) |
| No API docs / OpenAPI schema exposed in production | `app/main.py` | A05:2021 (recon surface reduction) |

## CI/CD pipeline (`.github/workflows/ci.yml`)

| Stage | Tool | Blocking? |
|---|---|---|
| Lint | ruff (incl. flake8-bandit rules) | Yes |
| Tests | pytest + coverage | Yes |
| SAST | bandit | Yes |
| SAST (broad) | semgrep (`p/security-audit`, `p/owasp-top-ten`, `p/python`) | No — tune the ruleset first |
| Dependency audit | pip-audit | Yes |
| Secret scanning | gitleaks | Yes |
| Container build + scan | Trivy (CRITICAL/HIGH) | Yes |
| SBOM | CycloneDX (via anchore/sbom-action) | N/A — artifact only |
| DAST | OWASP ZAP baseline against the running container | No — triage findings first |

Two jobs (`sast-semgrep`, `dast-zap-baseline`) are intentionally
non-blocking on day one. Broad SAST rulesets and DAST baselines both throw
false positives before you've tuned them to your codebase; shipping them
as blocking on day one either trains everyone to ignore CI or blocks
merges on noise. The honest AppSec move is: turn them on informational,
triage a week or two of findings, suppress the false positives with
justification, *then* flip them to blocking. Don't skip the second step.

## A real supply-chain lesson from building this pipeline

In March 2026, `aquasecurity/trivy-action` (the container scanner this
pipeline uses) was actually compromised: attackers force-pushed malicious
code onto 76 of 77 version *tags* in the repo. Anyone whose workflow
referenced a tag like `@0.28.0` during the ~12-hour exposure window ran
attacker-controlled code in their CI pipeline. The maintainers' fix was to
republish all tags with a `v` prefix (`v0.35.0`, `v0.36.0`, ...) pointing
back at verified-legitimate commits.

This pipeline was originally pinned to `@0.28.0` (bare, no `v`) — which
broke outright once the old tag scheme was retired, which is how this got
caught. The fix (`.github/workflows/ci.yml`) moved to `@v0.36.0`, with a
comment explaining why. The more thorough fix, worth doing before trusting
this pipeline with anything real, is pinning every third-party action in
this file to an exact commit SHA rather than any tag — tags can be moved
by anyone with write access to the upstream repo (or, as this incident
shows, by an attacker who compromises that access); commit SHAs cannot.

## Test-fixture secrets and secret scanners doing their job correctly

`gitleaks` (the `secret-scan` CI job) once flagged a string in
`tests/test_credentials.py` as a leaked Stripe key. It wasn't a real key —
it was test data verifying that `app/schemas.py` rejects raw-looking
secrets pasted into `vault_reference` — but gitleaks was *right* to flag
it: the fixture was deliberately shaped like `sk_live_...`, which is
exactly the pattern a real Stripe key follows. The fix was two-part: stop
using real-looking secret formats in test fixtures going forward (an
alphanumeric string with no provider-specific prefix tests the same
validation logic without ever matching a scanner's rules), and add the
historical commit's fingerprint to `.gitleaksignore` with a comment
explaining why, since git history is immutable and the old commit will be
rescanned on every future run. Every entry in that file needs a
justification — an unexplained fingerprint there is itself worth
questioning in review.

## What was actually verified vs. what's a reasonable default

Verified by running it: all 31 tests pass, ruff/bandit/pip-audit are all
clean against this exact dependency set, and I walked through the auth →
CSRF → RBAC → blast-radius → SQL-injection-attempt → audit-log → lockout
flow end-to-end with a real HTTP client and confirmed the behavior at each
step (see `README.md` for how to reproduce).

**Not verified**, because Docker isn't available in the environment this
was built in: the Dockerfile builds successfully, the container starts,
the healthcheck passes, the `read_only: true` + volume combination doesn't
break the SQLite write path. These are standard, well-worn patterns, not
exotic ones — but "standard pattern" and "tested" are different claims,
and you should run `docker compose up --build` yourself before trusting it
in front of anyone.

**Not implemented**, flagged rather than silently skipped: rate limiting
is IP-keyed in-memory (fine for a single instance, not for a multi-replica
*or serverless* deployment — on Vercel specifically, each request can hit
a different process, so the in-memory counter is best-effort only; the
per-account lockout in `app/auth.py` is DB-backed and is what actually
protects a Vercel deployment against brute force. Swapping in a
Redis-backed limiter, e.g. Upstash, closes this gap properly and was
deliberately deferred rather than added, since it's an infrastructure
decision, not a code one); there's no MFA; there's no password-reset flow
(an admin creates accounts with a temporary password).

## Where to take this next (roadmap ideas)

- Swap the rate limiter's storage backend to Redis before running more
  than one replica.
- Add MFA (TOTP) — `pyotp` is a light dependency for this.
- Add a "break glass" flow: a way to view a credential's blast radius
  during an incident without requiring login (behind a short-lived,
  audited token), for the 3am-outage case.
- Wire the audit log to ship to something outside the app's own database
  (so an attacker who gets write access to the DB can't also erase their
  tracks) — e.g. structured logs shipped to your SIEM.
- Add SSO (OIDC) as an alternative to local accounts once this leaves the
  portfolio-project stage.
