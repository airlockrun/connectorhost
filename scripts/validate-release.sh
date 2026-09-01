#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/dist}"

version_line="$(GOWORK=off go run "$ROOT_DIR/cmd/airlock-host" version)"
version="${version_line#airlock-host }"
if [[ -n "${RELEASE_VERSION:-}" && "$version" != "$RELEASE_VERSION" ]]; then
  echo "connectorhost source version is $version, not $RELEASE_VERSION" >&2
  exit 1
fi

package_version="${version#v}"
if [[ "$package_version" == *-* ]]; then
  package_version="${package_version%%-*}~${package_version#*-}"
fi

archives=(
  "airlock-host-$version-linux-amd64.tar.gz"
  "airlock-host-$version-linux-arm64.tar.gz"
  "airlock-host-$version-linux-armv7.tar.gz"
  "airlock-host-$version-darwin-amd64.tar.gz"
  "airlock-host-$version-darwin-arm64.tar.gz"
  "airlock-host-$version-windows-amd64.zip"
  "airlock-host-$version-windows-arm64.zip"
)
linux_labels=(linux-amd64 linux-arm64 linux-armv7)
deb_arches=(amd64 arm64 armhf)
artifacts=("${archives[@]}" install-airlock-host.ps1)

for label in "${linux_labels[@]}"; do
  artifacts+=("airlock-host-$version-$label.deb" "airlock-host-$version-$label.rpm")
done
checksum_artifacts=("${artifacts[@]}")
artifacts+=(SHA256SUMS)

for artifact in "${artifacts[@]}"; do
  if [[ ! -f "$OUTPUT_DIR/$artifact" ]]; then
    echo "missing release artifact: $artifact" >&2
    exit 1
  fi
done

(
  cd "$OUTPUT_DIR"
  sha256sum --check --strict SHA256SUMS
)

mapfile -t checksum_names < <(
  while read -r _ name; do
    echo "${name#./}"
  done < "$OUTPUT_DIR/SHA256SUMS"
)
if [[ "${#checksum_names[@]}" -ne "${#checksum_artifacts[@]}" ]]; then
  echo "SHA256SUMS contains an unexpected number of artifacts" >&2
  exit 1
fi
for artifact in "${checksum_artifacts[@]}"; do
  found=false
  for checksum_name in "${checksum_names[@]}"; do
    if [[ "$checksum_name" == "$artifact" ]]; then
      found=true
      break
    fi
  done
  if [[ "$found" != true ]]; then
    echo "SHA256SUMS does not cover $artifact" >&2
    exit 1
  fi
done

if command -v dpkg-deb >/dev/null 2>&1; then
  for index in "${!linux_labels[@]}"; do
    label="${linux_labels[$index]}"
    package="$OUTPUT_DIR/airlock-host-$version-$label.deb"
    if [[ "$(dpkg-deb --field "$package" Package)" != "airlock-host" ]]; then
      echo "unexpected Debian package name: $package" >&2
      exit 1
    fi
    if [[ "$(dpkg-deb --field "$package" Version)" != "$package_version-1" ]]; then
      echo "unexpected Debian package version: $package" >&2
      exit 1
    fi
    if [[ "$(dpkg-deb --field "$package" Architecture)" != "${deb_arches[$index]}" ]]; then
      echo "unexpected Debian package architecture: $package" >&2
      exit 1
    fi
    package_contents="$(dpkg-deb --fsys-tarfile "$package" | tar -tf -)"
    if [[ $'\n'"$package_contents"$'\n' != *$'\n./usr/bin/airlock-host\n'* ]]; then
      echo "Debian package does not contain /usr/bin/airlock-host: $package" >&2
      exit 1
    fi
  done
else
  echo "dpkg-deb is not installed; skipped Debian metadata inspection" >&2
fi

if command -v rpm >/dev/null 2>&1; then
  "$ROOT_DIR/scripts/validate-rpm.sh" "$OUTPUT_DIR" "$version"
elif [[ -n "${RPM_VALIDATOR_IMAGE:-}" ]]; then
  output_directory="$(cd "$OUTPUT_DIR" && pwd)"
  docker run --rm \
    --volume "$ROOT_DIR:/src:ro" \
    --volume "$output_directory:/dist:ro" \
    "$RPM_VALIDATOR_IMAGE" \
    /src/scripts/validate-rpm.sh /dist "$version"
else
  echo "rpm is not installed; skipped RPM metadata inspection" >&2
fi

for label in windows-amd64 windows-arm64; do
  archive="$OUTPUT_DIR/airlock-host-$version-$label.zip"
  archive_contents="$(unzip -Z1 "$archive")"
  if [[ $'\n'"$archive_contents"$'\n' != *$'\nairlock-host.exe\n'* ]]; then
    echo "Windows archive does not contain airlock-host.exe: $archive" >&2
    exit 1
  fi
  if [[ $'\n'"$archive_contents"$'\n' != *$'\ninstall-airlock-host.ps1\n'* ]]; then
    echo "Windows archive does not contain install-airlock-host.ps1: $archive" >&2
    exit 1
  fi
done

echo "validated airlock-host $version release artifacts in $OUTPUT_DIR"
