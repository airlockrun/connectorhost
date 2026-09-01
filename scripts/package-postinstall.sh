#!/bin/sh
set -eu

host=/usr/bin/airlock-host
unit=/etc/systemd/system/airlock-host.service
was_running=false
was_enabled=false
is_upgrade=false
case "${1:-}" in
  configure)
    if [ -n "${2:-}" ]; then
      is_upgrade=true
    fi
    ;;
  2) is_upgrade=true ;;
  1) ;;
  abort-upgrade|abort-remove|abort-deconfigure)
    exit 0
    ;;
  *)
    printf 'Airlock Host received an unsupported package lifecycle action: %s\n' "${1:-<empty>}" >&2
    exit 1
    ;;
esac

manager_online=false
manager_state="$(systemctl is-system-running 2>/dev/null || true)"
case "$manager_state" in
  initializing|starting|running|degraded|maintenance|stopping) manager_online=true ;;
  offline) ;;
  *)
    printf 'Airlock Host could not determine the systemd manager state: %s\n' "${manager_state:-<empty>}" >&2
    exit 1
    ;;
esac

if [ "$is_upgrade" = true ]; then
  enabled_state="$(systemctl is-enabled airlock-host.service 2>/dev/null || true)"
  case "$enabled_state" in
    enabled|enabled-runtime) was_enabled=true ;;
    disabled|not-found|static|indirect|generated|transient|linked|linked-runtime|alias) ;;
    masked|masked-runtime)
      printf 'Airlock Host cannot upgrade while airlock-host.service is masked.\n' >&2
      exit 1
      ;;
    *)
      printf 'Airlock Host could not determine whether its service is enabled: %s\n' "${enabled_state:-<empty>}" >&2
      exit 1
      ;;
  esac
fi
if [ -e "$unit" ] && [ "$manager_online" = true ]; then
  status="$("$host" service status)"
  case "$status" in
    running*|start-pending*) was_running=true ;;
    stopped|stop-pending|paused) ;;
    *)
      printf 'Airlock Host returned an unexpected service status: %s\n' "$status" >&2
      exit 1
      ;;
  esac
fi

"$host" service install >/dev/null

if [ "$is_upgrade" = true ] && [ "$was_enabled" = false ]; then
  systemctl disable airlock-host.service >/dev/null
fi

if [ "$manager_online" = false ]; then
  printf '%s\n' \
    'Airlock Host is installed, but no running systemd manager was detected.' \
    'The service will start at boot when enabled, or start it explicitly with:' \
    '  sudo airlock-host service start'
  exit 0
fi

if [ "$is_upgrade" = true ] && [ "$was_running" = false ]; then
  printf '%s\n' \
    'Airlock Host was upgraded and remains stopped.' \
    'Start it when ready with:' \
    '  sudo airlock-host service start'
  exit 0
fi

if [ -x /usr/sbin/policy-rc.d ] && ! /usr/sbin/policy-rc.d airlock-host start >/dev/null 2>&1; then
  printf '%s\n' \
    'Airlock Host is installed, but local service policy prevented startup.' \
    'Start and enroll it with:' \
    '  sudo airlock-host service start' \
    '  sudo airlock-host enroll --airlock https://YOUR-AIRLOCK'
  exit 0
fi

if [ "$was_running" = true ]; then
  "$host" service stop >/dev/null
fi
"$host" service start >/dev/null

printf '%s\n' \
  'Airlock Host is installed and running.' \
  'Enroll this machine with:' \
  '  sudo airlock-host enroll --airlock https://YOUR-AIRLOCK'
