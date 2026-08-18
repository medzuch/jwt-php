# 06 — Development Environment

Minimal local setup: **one tiny Dockerfile** that wraps the official
`php:<version>-cli-alpine` image and grafts in `composer:2`. The version is a
build arg defaulting to **8.3**, the floor of the supported window; a second
compose service (`php84`) builds the same recipe on **8.4**, the ceiling. No
custom INI tuning, no UID/GID juggling. Xdebug is installed but **off** by default
(zero perf cost) — flip it on per-command. Works the same on Windows +
WSL2, Linux, and macOS.

## Prerequisites

- Docker (Desktop on Windows/macOS, native on Linux).
- `make` (optional — every target is a thin wrapper around `docker compose`).

That's it. No PHP on the host required.

## First-time setup

```bash
make build      # build the dev image (first time only, ~30s)
make up         # start the container
make install    # composer install (inside the container)
make test       # run the suite
```

Without `make`:

```bash
docker compose build
docker compose up -d
docker compose exec php composer install
docker compose exec php vendor/bin/phpunit
```

## The other end of the supported window (PHP 8.4)

`composer.json` allows `~8.3.0 || ~8.4.0`, and CI runs the full gate on both.
Locally the 8.3 container is the default — it is the version a change breaks by
accident — and 8.4 lives behind a compose profile so `make up` stays a
one-container setup:

```bash
make qa-84                        # build/start php84, install, CS + PHPStan + tests
make test-84 ARGS="--filter=Jwk"  # just the suite, on 8.4
```

Without `make`:

```bash
docker compose --profile php84 up -d php84
docker compose exec php84 composer install
docker compose exec php84 composer qa
```

The `php84` service mounts its **own** `vendor/` (a named volume shadowing the
bind mount), so dependencies resolved by one runtime are never reused by the
other. That costs one extra `composer install` and buys the guarantee that a
green run on 8.4 means something.

**Run `make cs-fix` on 8.3 only** — that is, in the default container, never in
`php84`. php-cs-fixer rewrites code against the runtime it happens to be on, so
fixing on 8.4 can introduce syntax the floor cannot parse; the tool says so
itself when it starts above a project's declared minimum. Checking is safe
anywhere (`composer cs:check` is `--dry-run`, which is why `make qa-84` runs the
whole gate unchanged), and CI runs the style check on 8.3 for the same reason.

## Daily workflow

```bash
make sh                           # interactive shell inside the container
make test                         # run all tests
make test ARGS="--filter=ParserTest"
make qa                           # CS + PHPStan + tests
make cs-fix                       # apply code-style fixes
make phpstan                      # static analysis only
```

The container's `/app` is a bind mount of the project root, so edits on
the host are visible inside instantly.

## What ships in the image

The official `php:<version>-cli-alpine` already includes everything this
library's `require` block declares:

- `ext-json`, `ext-openssl`, `ext-sodium`, `ext-mbstring`

The Dockerfile adds only:

- `git` and `unzip` (so composer can install from dist).
- `xdebug` (loaded but off by default — `XDEBUG_MODE=off`).
- `ext-gmp` — **not a runtime dependency of this library** (our crypto is all
  `ext-openssl`). It exists solely so the benchmark suite (`benchmarks/`)
  measures web-token/jwt-framework fairly; without gmp/bcmath web-token's
  RSA/EC math falls back to pure-PHP bignum and is ~2000× slower. See
  [14 — Performance](14-performance.md).
- `composer` (copied from the official `composer:2` image).

That's the entire delta from upstream. No custom `php.ini`. No
opcache tuning. No baked-in Xdebug mode — the env var controls it.

## Xdebug

Xdebug ships in the image with `XDEBUG_MODE=off`, so there is zero
overhead until you ask for it. Toggle per-command:

```bash
# Step debugging:
docker compose exec -e XDEBUG_MODE=debug php \
    vendor/bin/phpunit --filter=MyTest

# Coverage:
docker compose exec -e XDEBUG_MODE=coverage php \
    vendor/bin/phpunit --coverage-html=var/coverage
# or simply:
make test-coverage
```

`host.docker.internal` is mapped via `extra_hosts` in `docker-compose.yml`,
so step-debugging works the same on Linux/WSL2 (where the gateway is
synthesised) as on Docker Desktop for Mac/Windows.

### PHPStorm step-debugging

1. Settings → PHP → Debug → port `9003`.
2. Settings → PHP → Servers → add a server, host `localhost`, map `/app`
   → project root, name it `jwt` (or whatever you like — Xdebug 3 doesn't
   need `PHP_IDE_CONFIG` because the path map is what matters).
3. Click the "Start Listening for PHP Debug Connections" toolbar icon.
4. Set a breakpoint and run a command with `-e XDEBUG_MODE=debug`.

## PHPStorm wiring (optional)

Open the project from WSL (`\\wsl$\<distro>\...`) or its native filesystem
on Linux/macOS.

1. **PHP interpreter** — Settings → PHP → CLI Interpreter → `+` → "From
   Docker, Vagrant, …" → "Docker Compose", configuration `docker-compose.yml`,
   service `php`. PHPStorm reads the PHP version and the loaded extensions
   automatically.
2. **PHPUnit** — Settings → PHP → Test Frameworks → `+` → "PHPUnit by
   Remote Interpreter" → reuse the interpreter from step 1. PHPUnit path:
   `/app/vendor/bin/phpunit`. Config file: `/app/phpunit.xml.dist`.
3. **PHPStan** — Settings → PHP → Quality Tools → PHPStan → reuse the
   same interpreter. Path: `/app/vendor/bin/phpstan`. Config:
   `/app/phpstan.neon.dist`. Inspections panel → enable at level 9.
4. **PHP-CS-Fixer** — Settings → PHP → Quality Tools → PHP CS Fixer →
   reuse the interpreter. Path: `/app/vendor/bin/php-cs-fixer`. Ruleset:
   "Custom" → `/app/.php-cs-fixer.dist.php`.

## Running without Docker

If you have PHP 8.3 or 8.4 with `ext-openssl`, `ext-sodium`, and
`ext-mbstring` on the host:

```bash
composer install
composer qa
```

All composer scripts work identically.

## Troubleshooting

### Files created inside the container are owned by root on the host

This is the classic bind-mount-as-root issue. Two options:
- Fix after the fact: `sudo chown -R "$(id -u):$(id -g)" .`
- Run individual composer commands with `--user "$(id -u):$(id -g)"`:
  `docker compose run --rm --user $(id -u):$(id -g) php composer install`

If this becomes a daily annoyance, add a `user:` line to `docker-compose.yml`
or reintroduce UID/GID build args in the Dockerfile. The default leaves
this out because most workflows don't generate host-visible files often.

### Composer is slow on first run

It's fetching packages over the network. The `composer-cache` named
volume in `docker-compose.yml` persists across container restarts and
rebuilds; subsequent installs reuse it.

### Files appear with CRLF line endings inside the container

`.editorconfig` and `.gitattributes` should prevent this. On Windows,
ensure `git config --global core.autocrlf input`, or use git from
inside WSL exclusively.
