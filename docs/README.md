# Documentation

This folder is the canonical design and operational reference for the library.
It is intentionally written as a small book, not a wiki — read it in order on
first contact.

| # | Document | Audience |
|---|----------|----------|
| 01 | [Architecture](01-architecture.md) | Anyone touching the code |
| 02 | [Threat Model](02-threat-model.md) | Anyone touching crypto-adjacent code |
| 03 | [RFC Compliance Matrix](03-rfc-compliance.md) | Reviewers, auditors |
| 04 | [Public API Surface](04-api-surface.md) | Library consumers |
| 05 | [Phased Roadmap](05-phased-roadmap.md) | Maintainers, planners |
| 06 | [Development Environment](06-development-environment.md) | New contributors |
| 07 | [Testing Strategy](07-testing-strategy.md) | Contributors |
| 08 | [Coding Standards](08-coding-standards.md) | Contributors |
| 09 | [Symfony Bundle Plan](09-symfony-bundle-plan.md) | Maintainers |
| 10 | [Security Policy](10-security-policy.md) | Everyone |
| 11 | [Glossary](11-glossary.md) | Anyone unfamiliar with JOSE |
| 12 | [Decisions](12-decisions.md) | Maintainers, reviewers — running log of trade-offs |

## Source RFCs

The authoritative sources for everything here:

- **RFC 7519** — JSON Web Token
- **RFC 7515** — JSON Web Signature
- **RFC 7516** — JSON Web Encryption
- **RFC 7517** — JSON Web Key
- **RFC 7518** — JSON Web Algorithms
- **RFC 7797** — JWS Unencoded Payload Option (updates 7519)
- **RFC 8725** — JSON Web Token Best Current Practices (BCP 225)
- **RFC 6979** — Deterministic ECDSA
- **NIST SP 800-56A r3** — Discrete-log key establishment (ECDH validation)
