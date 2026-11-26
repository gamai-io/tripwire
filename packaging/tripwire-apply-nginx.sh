#!/bin/sh
# Copy the tripwire deny list into nginx, but only if nginx still accepts the
# result. Runs as root from tripwire-apply.service (oneshot).
set -eu

SRC=${SRC:-/var/lib/tripwire/deny.conf}
DST=${DST:-/etc/nginx/conf.d/tripwire-deny.conf}
NGINX=${NGINX:-/usr/sbin/nginx}

[ -r "$SRC" ] || exit 0            # nothing written yet
if [ -f "$DST" ] && cmp -s "$SRC" "$DST"; then
    exit 0                          # unchanged; do not reload
fi

backup=""
if [ -f "$DST" ]; then
    backup=$(mktemp)
    cp -p "$DST" "$backup"
fi

install -m 0644 "$SRC" "$DST"
if ! "$NGINX" -t; then
    if [ -n "$backup" ]; then
        install -m 0644 "$backup" "$DST"
    else
        rm -f "$DST"
    fi
    rm -f "$backup"
    echo "tripwire: nginx -t rejected the new deny list; previous file restored" >&2
    exit 1
fi
rm -f "$backup"
"$NGINX" -s reload
