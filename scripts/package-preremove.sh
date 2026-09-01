#!/bin/sh
set -eu

case "${1:-}" in
  remove|0)
    if [ -x /usr/bin/airlock-host ]; then
      host=/usr/bin/airlock-host
    elif [ -x /usr/local/bin/airlock-host ]; then
      host=/usr/local/bin/airlock-host
    else
      host=
    fi
    if [ -n "$host" ] && ! "$host" service uninstall; then
      printf '%s\n' 'Airlock Host could not contact systemd during removal; removing its unit registration.' >&2
      systemctl disable airlock-host.service >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/airlock-host.service
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    ;;
esac
