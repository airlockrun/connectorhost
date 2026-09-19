#!/bin/sh
set -eu

case "${1:-}" in
  purge)
    state=/var/lib/airlock-host
    host=/usr/local/bin/airlock-host
    rm -rf "$state"
    rm -f "$host"
    ;;
  remove|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear|0|1)
    ;;
  *)
    printf 'Airlock Host received an unsupported post-removal action: %s\n' "${1:-<empty>}" >&2
    exit 1
    ;;
esac
