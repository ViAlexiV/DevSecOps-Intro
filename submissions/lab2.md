# Lab 2 Submission

## Task 1

### Baseline severity counts

Total risks: `23`

| Severity | Count |
|---|---:|
| elevated | 4 |
| medium | 14 |
| low | 5 |

### Top five risks

| Severity | Rule ID | Asset | Risk |
|---|---|---|---|
| elevated | `unencrypted-communication` | `user-browser` | Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data |
| elevated | `unencrypted-communication` | `reverse-proxy` | Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application |
| elevated | `cross-site-scripting` | `juice-shop` | Cross-Site Scripting (XSS) risk at Juice Shop Application |
| elevated | `missing-authentication` | `juice-shop` | Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application |
| medium | `missing-authentication-second-factor` | `juice-shop` | Missing Two-Factor Authentication covering communication link Direct to App (no proxy) from User Browser to Juice Shop Application |

### STRIDE mapping

1. `unencrypted-communication` on `user-browser`: **I - Information Disclosure**. The direct browser-to-app path carries authentication data over a link modeled as clear text, so an attacker on that path could observe session or credential material.
2. `unencrypted-communication` on `reverse-proxy`: **I - Information Disclosure**. The reverse-proxy-to-application hop is inside the deployment, but without encryption it can still expose tokens and application data to anyone who gains network visibility there.
3. `cross-site-scripting` on `juice-shop`: **T - Tampering**. XSS lets an attacker inject script into trusted application pages, modifying what users see or what actions their browser performs.
4. `missing-authentication` on `juice-shop`: **S - Spoofing**. The reverse proxy to app communication link lacks authentication, so the application cannot strongly distinguish a trusted proxy request from an impersonating caller.
5. `missing-authentication-second-factor` on `juice-shop`: **S - Spoofing**. Without a second factor, stolen or guessed credentials are enough for an attacker to impersonate a user on the direct app path.

### Trust boundary crossing

The `Direct to App (no proxy)` arrow from `User Browser` to `Juice Shop Application` crosses from the untrusted Internet/user side into the host/container environment. It is worth an attacker's time because it appears in the top five as `unencrypted-communication` and carries authentication data; capturing or tampering with that path could lead to session compromise.

## Task 2

### Baseline vs secure counts

| Severity | Baseline | Secure | Delta |
|---|---:|---:|---:|
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| total | 23 | 18 | -5 |

The total dropped from 23 to 18 risks, a reduction of about 22%.

### Removed rules

- `unencrypted-communication`: removed by changing inbound application links from `protocol: http` to `protocol: https` for `Direct to App (no proxy)` and `To App`.
- `missing-authentication`: removed by changing the reverse proxy to application link from `authentication: none` to `authentication: token`.
- `unencrypted-asset`: removed by changing `encryption: none` to `encryption: data-with-symmetric-shared-key` on `Juice Shop Application` and `Persistent Storage`.

### Rules that still fire

- `cross-site-scripting`: still fires because transport encryption and asset-at-rest encryption do not remove XSS in the application itself. This needs application-level output encoding, input validation, CSP, and vulnerable feature fixes.
- `cross-site-request-forgery`: still fires because changing protocols and encryption does not prove that state-changing app routes use anti-CSRF protections. This needs application controls such as CSRF tokens, SameSite cookies, and strict server-side validation.

### What risk is left

The secure model removes several infrastructure and communication risks, especially cleartext traffic, unauthenticated internal service calls, and unencrypted storage. The remaining risk is mostly application, supply-chain, and operational risk: XSS, CSRF, missing hardening, missing vault, and container base image concerns. Closing those would require code changes, runtime hardening, secret management, dependency and image scanning, and stronger application security controls. A risk like XSS in Juice Shop application code cannot be closed by a YAML architecture edit alone.

## Bonus

### Authentication model severity counts

| Severity | Count |
|---|---:|
| high | 1 |
| elevated | 8 |
| medium | 18 |
| low | 10 |

### Auth-specific risks

1. `path-traversal` on `token-service`: **I - Information Disclosure**. The feature-level model shows the token service reading the JWT signing key from a filesystem-backed key store, so path traversal could expose signing material. Mitigation: keep signing keys in a real secret manager, restrict filesystem paths, and validate/canonicalize any file access.
2. `sql-nosql-injection` on `login-endpoint`: **T - Tampering**. The login endpoint validates credentials against the credential store, so injection on this path could alter authentication queries or bypass login checks. Mitigation: use parameterized queries, strict input validation, and least-privilege database access.
3. `server-side-request-forgery` on `admin-endpoint`: **I - Information Disclosure**. The admin endpoint calls the token service to verify JWTs, which creates an internal server-side request path that the architecture model did not describe at feature level. Mitigation: allowlist internal service targets, avoid user-controlled URLs, and enforce strict network egress controls.

### Feature-level insight

The feature-level model exposed risks around token issuing, token verification, JWT signing key access, and admin authorization checks that the architecture-level model could only represent generically. It showed how specific login-flow links create injection, SSRF, and key-access risks even when the broader deployment uses HTTPS and encrypted storage.
