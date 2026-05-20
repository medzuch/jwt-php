# Minimal dev image: official PHP 8.3 CLI + composer + Xdebug.
# php:8.3-cli-alpine already ships json, openssl, sodium, mbstring built-in —
# everything this library's `require` block declares. We only add:
#   - git + unzip (so composer can install from dist)
#   - Xdebug   (loaded but off by default; toggle per-run with XDEBUG_MODE)
#   - composer (grafted from the official `composer:2` image)
FROM php:8.3-cli-alpine

RUN apk add --no-cache git unzip \
 && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS linux-headers \
 && pecl install xdebug \
 && docker-php-ext-enable xdebug \
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
