# Benchmarks

A cross-library micro-benchmark comparing **medzuch/jwt-php** against
**firebase/php-jwt** and **web-token/jwt-framework** for issuing and verifying
compact JWS across HS256 / RS256 / ES256.

This is an **isolated sub-project**: it has its own `composer.json` so the two
competitor libraries (and web-token's large dependency tree) are pulled into
`benchmarks/vendor/`, never into the library's own dev dependencies. The parent
library is referenced through a Composer path repository.

Results and analysis live in [`../docs/14-performance.md`](../docs/14-performance.md).

## Running

```bash
# 1. install the harness dependencies (one-time)
docker compose exec php sh -c 'cd /app/benchmarks && composer install'

# 2. run
docker compose exec php php benchmarks/run.php

# tighter numbers: spend more wall-clock per operation (default 1.0s)
docker compose exec php env BENCH_BUDGET=3.0 php benchmarks/run.php
```

stdout is a Markdown table (paste-ready for the docs); progress goes to stderr.

## Requirements

- **`ext-gmp`** — required for a *fair* result. Without it, web-token's RSA/EC
  math falls back to pure-PHP `brick/math` and is ~2000× slower, which is an
  environment artifact rather than a property of the library. The project's
  `docker/Dockerfile` ships `ext-gmp` for exactly this reason. medzuch/jwt-php
  and firebase/php-jwt use `ext-openssl` and do not need it.

## Layout

| File | Role |
|---|---|
| `composer.json` / `composer.lock` | Isolated deps (competitors + path-ref to parent); the lock pins the exact versions the published numbers were taken with. |
| `src/Keys.php` | Generates the RSA-2048 / EC-P256 / HMAC-256 key material shared by all libraries. |
| `src/Bench.php` | Adaptive timing runner (time-bounded warmup, per-op deadline checks). |
| `run.php` | Wires each library × algorithm into issue/verify closures and runs them. |
| `report.php` | Renders results as a Markdown table with relative-throughput factors. |
