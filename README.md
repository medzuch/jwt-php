# Medzuch JWT

[![CI](https://github.com/medzuch/jwt-php/actions/workflows/ci.yml/badge.svg)](https://github.com/medzuch/jwt-php/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%5E8.3-blue)](https://www.php.net/releases/8.3/)

A standalone, modern JWT library for PHP 8.3+, built strictly to:

- **RFC 7519** — JSON Web Token
- **RFC 7515 / 7516 / 7517 / 7518** — JWS, JWE, JWK, JWA (underlying JOSE)
- **RFC 7797** — JWS Unencoded Payload Option (supported at the JWS layer; refused at the JWT layer per RFC 7519's update)
- **RFC 8725** — JWT Best Current Practices (BCP 225)

Framework-agnostic by design. A separate `medzuch/jwt-bundle` package will provide the Symfony 7.x integration.

## Why another JWT library?

Most PHP JWT libraries predate **RFC 8725** and still encourage `alg`-driven verification — the
root cause of the algorithm-confusion attacks the BCP exists to stop. This library:

- Refuses `alg:none` and algorithm switching by construction (caller declares an allowlist).
- Binds every key to its algorithm (one key, one purpose — BCP §3.1).
- Treats `b64:false` as forbidden in JWTs (RFC 7519, updated by 7797).
- Separates JWS, JWT, and Profile layers so that an application-level "access token" is a single
  type with a single validator, not a permissive bag of claims.
- Ships with explicit typing (`typ` enforcement, `application/<x>+jwt`).
- Refuses unsafe defaults: no `jku`/`x5u` fetching, no compression in JWE, no password-as-HMAC-key.

See **[docs/](docs/)** for the full design, threat model, and per-RFC compliance notes.

## Quickstart (Docker)

```bash
make build                    # build the PHP 8.3 dev image (one-time, ~30s)
make up                       # start the container
make install                  # composer install
make test                     # run the suite
make qa                       # CS + PHPStan level 9 + tests
```

Or without Docker, assuming PHP 8.3 with `ext-sodium`, `ext-openssl`, `ext-mbstring`:

```bash
composer install
composer qa
```

## Status

> **v0.2.0 — Phases 1–2 complete.** HS/RS/ES/EdDSA signing, explicit typing,
> profiles (access-token, ID-token, SET), and key resolvers (static, remote
> JWKS, composite). Phase 3 (JWE) is next — see
> [docs/05-phased-roadmap.md](docs/05-phased-roadmap.md).
>
> The library is **not yet ready for production**. Public API will stabilise at v1.0.0.

## Documentation

- [01 — Architecture](docs/01-architecture.md)
- [02 — Threat Model](docs/02-threat-model.md)
- [03 — RFC Compliance Matrix](docs/03-rfc-compliance.md)
- [04 — Public API Surface](docs/04-api-surface.md)
- [05 — Phased Roadmap](docs/05-phased-roadmap.md)
- [06 — Development Environment](docs/06-development-environment.md)
- [07 — Testing Strategy](docs/07-testing-strategy.md)
- [08 — Coding Standards](docs/08-coding-standards.md)
- [09 — Symfony Bundle Plan](docs/09-symfony-bundle-plan.md)
- [10 — Security Policy](docs/10-security-policy.md)
- [11 — Glossary](docs/11-glossary.md)
- [12 — Decisions](docs/12-decisions.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/08-coding-standards.md](docs/08-coding-standards.md).

## Security

Security issues: **do not open a public issue**. See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
