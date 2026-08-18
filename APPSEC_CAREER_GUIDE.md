# Using CredTrace to break into AppSec — a roadmap

This project is a vehicle, not the destination. Here's how to get real
mileage out of it, roughly in order.

## 1. Actually attack your own app

Before you polish anything else, spend a weekend trying to break
CredTrace. This is worth more than any certification for building
intuition.

- Try to bypass the RBAC checks (edit form fields in devtools, replay
  requests with a viewer's session against editor-only routes).
- Try the CSRF flow manually with a second browser profile or `curl`.
- Try SQL injection payloads in every text field, not just search.
- Try to break the account lockout (does it reset if you wait exactly the
  lockout window? does the counter behave correctly under concurrent
  requests?).
- Read `THREAT_MODEL.md`, pick one "accepted risk," and actually build the
  exploit or the fix. Both are useful to have done.
- Once you're comfortable, try OWASP ZAP or Burp Suite Community against
  your local instance (the CI's `dast-zap-baseline` job does this
  automatically — read its output).

Write up what you found, even the things you fixed yourself. A short
"here's a CSRF bypass I found in my own project and how I fixed it" post
is a stronger portfolio artifact than the project itself.

## 2. Fill the gaps this project leaves deliberately open

Each of these is scoped to be doable in a weekend and teaches something
distinct:

- **Add MFA (TOTP)** — teaches you the mechanics behind an auth factor
  most AppSec job postings assume you understand.
- **Move rate limiting to Redis** (e.g. Upstash) — the project already
  documents *why* this matters specifically on a serverless deploy
  (`README.md`'s Vercel section, `THREAT_MODEL.md`'s DoS rows); actually
  wiring it up teaches distributed-systems security thinking (why does an
  in-memory limiter fail across replicas or serverless invocations, and
  why is a DB-backed control like the account lockout different?).
- **Add dependency-review gating on PRs** (GitHub's `dependency-review-action`)
  — teaches supply-chain policy, not just scanning.
- **Threat-model a feature *before* building it** — pick something from
  the SECURITY.md roadmap, write the STRIDE rows first, then build. (This
  project's own last-active-admin bug, in `THREAT_MODEL.md`, is a real
  example of what that process catches.)

## 3. Learn the standards this project is already mapped to

You don't need to memorize these, but you should be fluent in navigating
them:

- **OWASP ASVS** (Application Security Verification Standard) — the
  control-by-control checklist SECURITY.md's table is drawn from. Read
  Level 1 and 2 in full at least once.
- **OWASP Top 10** — know it well enough to map a finding to a category
  without looking it up.
- **CWE/SANS Top 25** — useful vocabulary for describing root causes
  precisely in a finding writeup ("this is CWE-89" reads very differently
  in a report than "this is a SQL injection thing").
- **NIST 800-63B** — this project's password policy
  (`app/security.py::password_policy_errors`) follows its length-over-
  complexity guidance; know *why* that guidance exists so you can defend
  it when someone asks for mandatory special characters.

## 4. Learn the tools this pipeline already runs

You've now run each of these against a real (if small) codebase — that's
different from having read about them:

| Tool | Category | What to learn next about it |
|---|---|---|
| bandit | SAST (Python) | How to write a custom bandit plugin for an org-specific anti-pattern |
| semgrep | SAST (broad) | Write a custom rule for a bug class specific to your stack |
| pip-audit | SCA | How SBOM data (the CycloneDX output from CI) feeds into this |
| gitleaks | Secret scanning | How to write a custom regex rule, and how pre-commit hooks stop leaks before they're even pushed |
| Trivy | Container scanning | The difference between OS-package and language-package findings, and why `ignore-unfixed` is a real trade-off, not just noise reduction |
| OWASP ZAP | DAST | The difference between a baseline scan (what CI runs) and a full active scan (what you'd run manually, with authorization, against a target that expects it) |

## 5. Positioning this in interviews / applications

- Don't lead with "I built a password manager." It isn't one, and the
  distinction (metadata vs. secrets) *is* the interesting security
  decision — lead with that instead.
- Have the CSRF bypass story, the timezone bug story, or the last-admin
  logic gap ready as a "tell me about a bug you found" answer. Interviewers
  respond better to "here's a real subtle thing I got wrong and how I
  caught it" than to a project that claims to have no flaws.
- Be ready to walk through `THREAT_MODEL.md` live and defend the "accepted
  risk" rows — an interviewer poking at exactly those rows is a *good*
  sign, not a gotcha.
- If asked "what would you do differently at scale," you already have real
  answers in SECURITY.md's roadmap section (Redis-backed rate limiting,
  external audit-log shipping, SSO) — these came from actually building
  the thing, not from a generic checklist.

## 6. Where to go after this project

- Try a deliberately-vulnerable app (OWASP Juice Shop, WebGoat, DVWA) from
  the *attacker* side, now that you've built something from the defender
  side. Both perspectives sharpen each other.
- Look at real disclosed CVEs for frameworks you used here (FastAPI,
  SQLAlchemy, Starlette) and read the actual patches — seeing what a real
  fix looks like for a framework you already know well is very different
  from reading about vulnerability classes in the abstract.
- If you want a title-shaped next step: "Application Security Engineer,"
  "Product Security Engineer," and "AppSec Analyst" are the roles this
  project most directly speaks to. "Security Engineer" more broadly often
  expects infra/cloud breadth this project doesn't cover — pair this with
  a small cloud-security project (IAM policy review, a Terraform module
  with `tfsec`/`checkov` wired in) if that's the direction you want.
