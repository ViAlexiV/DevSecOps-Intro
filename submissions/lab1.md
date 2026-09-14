# Lab 1 Submission

## Triage report

### Asset

- Image tag: `bkimminich/juice-shop:v20.0.0`
- Image digest: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Host OS: macOS 27.0, arm64
- Docker version: Docker version 29.7.2, build a7dcaa6

### Deployment

- Run command:

```bash
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.0.0
```

- Access URL: `http://127.0.0.1:3000`
- Port binding: `127.0.0.1:3000->3000/tcp`
- The port is bound to localhost only, so the intentionally vulnerable training app is reachable from this host but is not exposed on all network interfaces such as Wi-Fi.
- Restart policy: `no`

### Health

```text
NAMES        STATUS             PORTS
juice-shop   Up About an hour   127.0.0.1:3000->3000/tcp
```

```text
HTTP 200
```

```json
{"version":"20.0.0"}
```

```text
46
```

### Surface

- Login and registration: the account area exposes a login page at `/#/login` with email, password, forgot-password, remember-me, and Google login controls. The registration page at `/#/register` asks for email, password, repeated password, a security question, and an answer.
- Products: the home page shows the product catalog with pagination. The first page displayed `1 - 15 of 46`, matching the API product count.
- Admin or account area: direct navigation to `/#/administration` showed `403 You are not allowed to access this page!` while unauthenticated.
- Console errors: no browser console warning/error entries were observed during the manual page checks. Triggering `GET /api/Products/1/reviews` returned `HTTP 500`, and the app showed an Error Handling challenge notification.
- Local storage and cookies: Safari Web Inspector showed an empty Local Storage table for `127.0.0.1`. Cookies for `127.0.0.1` contained `continueCode`, `cookieconsent_status=dismiss`, `language=en`, and `welcomebanner_status=dismiss`; `continueCode` was a long opaque value starting with `O3VMEvaD` and ending with `nrK4a2x`, while the other cookies stored UI preferences such as consent, language, and welcome banner dismissal.
- Product review request: `GET /rest/products/1/reviews` returned `HTTP 200` without authentication and included review messages and author email addresses.

### Headers

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
X-Recruiting: /#/jobs
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 14 Sep 2026 03:35:21 GMT
ETag: W/"26af-1a09dfbd315"
Content-Type: text/html; charset=UTF-8
Content-Length: 9903
Vary: Accept-Encoding
Date: Mon, 14 Sep 2026 04:43:17 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

Header classification:

- `Content-Security-Policy`: missing
- `Strict-Transport-Security`: missing
- `X-Content-Type-Options`: present, `nosniff`
- `X-Frame-Options`: present, `SAMEORIGIN`

### Top 3 risks

1. Missing browser hardening headers: `Content-Security-Policy` and `Strict-Transport-Security` are not present in the response. Missing CSP weakens browser-side protection against injected script execution, and missing HSTS means HTTPS-only behavior is not enforced when the app is deployed behind TLS. Category: A02:2025 Security Misconfiguration.

2. Unauthenticated access to review data: `GET /rest/products/1/reviews` returned review messages and author email addresses without requiring a logged-in session. If this data were not intended to be public, anonymous access would expose user-identifying information and support account or email enumeration. Category: A01:2025 Broken Access Control.

3. Ungraceful exceptional condition: `GET /api/Products/1/reviews` returned `HTTP 500`, and the app surfaced an Error Handling challenge notification. Unexpected server errors can disclose behavior, make monitoring noisy, and show that some invalid states are not handled cleanly. Category: A10:2025 Mishandling of Exceptional Conditions.

## PR template

- File path: `.github/PULL_REQUEST_TEMPLATE.md`
- Section names: Goal, Changes, Testing, Artifacts & Screenshots
- Checklist items:
  - Title follows `feat(labN): <topic>`
  - No secrets or large temp files committed
  - `submissions/labN.md` exists
- Draft PR proof: REPLACE BEFORE SUBMISSION with a draft PR link or screenshot showing the auto-filled description.

## GitHub community

Stars matter to open-source maintainers because they make a project easier to discover and give maintainers a visible signal that the work is useful. Following classmates and course staff helps team projects because it makes repositories, activity, and collaboration updates easier to find.
