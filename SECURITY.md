# Security Policy

## Supported versions

| Version | Status |
| ------- | ------ |
| 0.x     | Pre-release. Best-effort fixes; no guarantees. |
| 1.x     | Full security support once released. |

## Reporting a vulnerability

**Do not open a public GitHub issue.** Please use GitHub's private
vulnerability reporting:

→ **[Report a vulnerability](https://github.com/medzuch/jwt-php/security/advisories/new)**

(Also reachable from the repo's *Security → Advisories → Report a
vulnerability* button.)

Include:

- A description of the issue.
- A proof-of-concept or steps to reproduce.
- The affected version(s) and your environment.
- Any suggested mitigation.

This is a one-person project. I'll acknowledge reports as soon as I see
them and fix when I can — usually quickly for anything high-severity, but
there are no guaranteed timelines while the library is pre-1.0. If you
don't hear back within a week, feel free to nudge in the advisory thread. :)

## Disclosure

We follow **coordinated disclosure**. Once a fix is released, we will:

1. Publish a GitHub Security Advisory.
2. Credit the reporter (unless they prefer to stay anonymous).
3. Request a CVE ID where appropriate.

## Scope

In scope:
- Cryptographic correctness of JWS/JWE/JWT operations.
- Bypasses of the algorithm allowlist, key/algorithm binding, or `typ` enforcement.
- Side-channel leaks in signature verification or key handling.
- Parser vulnerabilities (DoS, panic, type confusion).

Out of scope (report upstream):
- Vulnerabilities in `ext-openssl`, `ext-sodium`, OpenSSL, or libsodium.
- Issues in applications that use this library incorrectly (e.g. that bypass
  the safe API and call internals directly).
