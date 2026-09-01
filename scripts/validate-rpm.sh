#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:?usage: validate-rpm.sh OUTPUT_DIR VERSION}"
version="${2:?usage: validate-rpm.sh OUTPUT_DIR VERSION}"

package_version="${version#v}"
if [[ "$package_version" == *-* ]]; then
  package_version="${package_version%%-*}~${package_version#*-}"
fi

linux_labels=(linux-amd64 linux-arm64 linux-armv7)
rpm_arches=(x86_64 aarch64 armv7hl)

for index in "${!linux_labels[@]}"; do
  label="${linux_labels[$index]}"
  package="$OUTPUT_DIR/airlock-host-$version-$label.rpm"
  metadata="$(rpm -qp --queryformat '%{NAME}\n%{VERSION}-%{RELEASE}\n%{ARCH}\n' "$package")"
  expected=$'airlock-host\n'"$package_version-1"$'\n'"${rpm_arches[$index]}"
  if [[ "$metadata" != "$expected" ]]; then
    echo "unexpected RPM metadata in $package:" >&2
    echo "$metadata" >&2
    exit 1
  fi
  if [[ "$(rpm -qlp "$package")" != "/usr/bin/airlock-host" ]]; then
    echo "unexpected RPM payload in $package" >&2
    exit 1
  fi
  if [[ -n "$(rpm -qp --scripts "$package")" ]]; then
    echo "RPM package contains an unexpected scriptlet: $package" >&2
    exit 1
  fi
done

echo "validated RPM metadata and payloads for airlock-host $version"
