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

The `Direct to App (no proxy)` arrow from `User Browser` to `Juice Shop Application` crosses from the untrusted Internet/user side into the host/container environment. It is worth an attacker's time because it appears in the top five as `unencrypted-communication` and carries authentication data; capturing or tampering with that path could

