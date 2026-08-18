# Minimal dev image: official PHP CLI + composer + Xdebug.
# php:<version>-cli-alpine already ships json, openssl, sodium, mbstring built-in —
# everything this library's `require` block declares. We only add:
#   - git + unzip (so composer can install from dist)
#   - Xdebug   (loaded but off by default; toggle per-run with XDEBUG_MODE)
#   - gmp      (NOT used by the library itself — openssl covers all our crypto.
#              It exists only so the benchmark suite (benchmarks/) measures
#              web-token/jwt-framework fairly: without gmp/bcmath, web-token's
#              RSA/EC math falls back to pure-PHP bignum and is ~2000x slower,
#              which would be an environment artifact, not a real comparison.)
#   - composer (grafted from the official `composer:2` image)
# The supported window is PHP 8.3 and 8.4 (see composer.json). The default is
# the *floor*, because that is the version a change can break by accident;
# override to test the ceiling:
#   docker compose --profile php84 up -d php84   (see docker-compose.yml)
#   docker build --build-arg PHP_VERSION=8.4 ./docker
ARG PHP_VERSION=8.3

FROM php:${PHP_VERSION}-cli-alpine

RUN apk add --no-cache git unzip gmp \
 && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers gmp-dev \
 && pecl install xdebug \
 && docker-php-ext-enable xdebug \
 && docker-php-ext-install gmp \
 && apk del --no-network .build-deps

# Xdebug 3 honours the XDEBUG_MODE env var directly, so no `xdebug.mode`
# line here — flip it per-command with `-e XDEBUG_MODE=debug|coverage`.
RUN { \
      echo 'xdebug.client_host=host.docker.internal'; \
      echo 'xdebug.client_port=9003'; \
      echo 'xdebug.start_with_request=trigger'; \
    } > /usr/local/etc/php/conf.d/xdebug.ini

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

WORKDIR /app
