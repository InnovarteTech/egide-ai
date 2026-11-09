FROM node:22-bookworm-slim AS assets
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY vite.config.js ./
COPY resources resources
COPY public public
RUN npm run build

FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-interaction --prefer-dist --no-autoloader --ignore-platform-reqs
COPY . .
RUN composer dump-autoload --optimize --no-dev --classmap-authoritative

FROM php:8.3-apache-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev libzip-dev unzip \
    && docker-php-ext-install pdo_pgsql pcntl zip opcache \
    && pecl install redis-6.1.0 && docker-php-ext-enable redis \
    && a2enmod rewrite headers \
    && rm -rf /var/lib/apt/lists/* /tmp/pear
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf \
    && printf '%s\n' 'ServerName localhost' 'ServerTokens Prod' 'ServerSignature Off' \
        'Header always set X-Content-Type-Options "nosniff"' \
        'Header always set X-Frame-Options "DENY"' \
        'Header always set Referrer-Policy "strict-origin-when-cross-origin"' \
        'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"' \
        "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'\"" \
        'SetEnvIf X-Forwarded-Proto "^https$" EGIDE_HTTPS' \
        'Header always set Strict-Transport-Security "max-age=31536000" env=EGIDE_HTTPS' \
        > /etc/apache2/conf-enabled/zz-egide-security.conf \
    && printf 'expose_php=Off\nmemory_limit=256M\nopcache.enable=1\nopcache.validate_timestamps=0\n' > /usr/local/etc/php/conf.d/egide.ini
WORKDIR /var/www/html
COPY --from=vendor --chown=www-data:www-data /app /var/www/html
COPY --from=assets --chown=www-data:www-data /app/public/build /var/www/html/public/build
COPY docker/entrypoint.sh /usr/local/bin/egide-entrypoint
RUN chmod +x /usr/local/bin/egide-entrypoint && rm -rf runner tests node_modules .env
ENTRYPOINT ["egide-entrypoint"]
CMD ["apache2-foreground"]
