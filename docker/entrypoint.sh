#!/bin/sh
set -e
cd /var/www/html
mkdir -p storage/app/private/frames storage/framework/cache storage/framework/sessions storage/framework/views storage/logs bootstrap/cache
if [ "$(id -u)" = "0" ]; then
    chown -R www-data:www-data storage bootstrap/cache
fi
if [ "${EGIDE_ROLE:-app}" = "app" ]; then
    php artisan migrate --force --no-interaction
    if [ "${EGIDE_SEED_ADMIN:-false}" = "true" ]; then
        php artisan db:seed --force --no-interaction
    fi
fi
php artisan config:cache
php artisan route:cache
php artisan view:cache
exec "$@"
