# 06 — Development Environment

Minimal local setup: **one tiny Dockerfile** that wraps the official
`php:8.3-cli-alpine` image and grafts in `composer:2`. No custom INI
tuning, no UID/GID juggling. Xdebug is installed but **off** by default
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

The official `php:8.3-cli-alpine` already includes everything this
library's `require` block declares:

- `ext-json`, `ext-openssl`, `ext-sodium`, `ext-mbstring`

The Dockerfile adds only:

- `git` and `unzip` (so composer can install from dist).
- `xdebug` (loaded but off by default — `XDEBUG_MODE=off`).
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
   service `php`. PHPStorm reads PHP 8.3 and the loaded extensions
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

If you have PHP 8.3 with `ext-openssl`, `ext-sodium`, and `ext-mbstring`
on the host:

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
