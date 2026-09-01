#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/dist}"
NFPM="${NFPM:-nfpm}"
NFPM_TOOL_VERSION="2.47.0"
NFPM_MODULE_SUM="h1:0bioJAjWaMPntgDqynP4ze0Wt4zYqYSFJ5/BBy9XIGI="

if ! command -v "$NFPM" >/dev/null 2>&1; then
  echo "nFPM $NFPM_TOOL_VERSION is required; install it with:" >&2
  echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v$NFPM_TOOL_VERSION" >&2
  exit 1
fi
nfpm_version="$($NFPM --version 2>&1)"
if [[ ! "$nfpm_version" =~ (^|[[:space:]])v?2\.47\.0($|[[:space:]]) ]] &&
  [[ "$nfpm_version" != *"ModuleSum:     $NFPM_MODULE_SUM"* ]]; then
  echo "nFPM $NFPM_TOOL_VERSION is required, found: $nfpm_version" >&2
  exit 1
fi

if [[ -e "$OUTPUT_DIR" ]]; then
  echo "output path already exists: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$OUTPUT_DIR"

version_line="$(GOWORK=off go run "$ROOT_DIR/cmd/airlock-host" version)"
version="${version_line#airlock-host }"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|alpha|beta|dev)\.[0-9]+)?$ ]]; then
  echo "invalid connectorhost version: $version" >&2
  exit 1
fi
if [[ -n "${RELEASE_VERSION:-}" && "$version" != "$RELEASE_VERSION" ]]; then
  echo "connectorhost source version is $version, not $RELEASE_VERSION" >&2
  exit 1
fi

package_version="${version#v}"
if [[ "$package_version" == *-* ]]; then
  package_version="${package_version%%-*}~${package_version#*-}"
fi

package_linux() {
  local binary="$1"
  local label="$2"
  local arch="$3"
  local packager

  for packager in deb rpm; do
    NFPM_ARCH="$arch" NFPM_BINARY="$binary" NFPM_PACKAGE_VERSION="$package_version" \
      "$NFPM" package --config "$ROOT_DIR/nfpm.yaml" --packager "$packager" \
      --target "$OUTPUT_DIR/airlock-host-$version-$label.$packager"
  done
}

build_target() {
  local goos="$1"
  local goarch="$2"
  local label="$3"
  local binary="airlock-host"
  local directory="$OUTPUT_DIR/airlock-host-$version-$label"
  local archive

  if [[ "$goos" == "windows" ]]; then
    binary="airlock-host.exe"
  fi
  mkdir -p "$directory"

  if [[ "$label" == "linux-armv7" ]]; then
    GOOS="$goos" GOARCH=arm GOARM=7 CGO_ENABLED=0 GOWORK=off \
      go build -trimpath -ldflags="-s -w" -o "$directory/$binary" "$ROOT_DIR/cmd/airlock-host"
  else
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 GOWORK=off \
      go build -trimpath -ldflags="-s -w" -o "$directory/$binary" "$ROOT_DIR/cmd/airlock-host"
  fi

  if [[ "$goos" == "windows" ]]; then
    cp "$ROOT_DIR/scripts/install-airlock-host.ps1" "$directory/install-airlock-host.ps1"
    archive="$OUTPUT_DIR/airlock-host-$version-$label.zip"
    (cd "$directory" && zip -q -9 "$archive" "$binary" install-airlock-host.ps1)
  else
    archive="$OUTPUT_DIR/airlock-host-$version-$label.tar.gz"
    tar -C "$OUTPUT_DIR" -czf "$archive" "$(basename "$directory")"
  fi

  if [[ "$goos" == "linux" ]]; then
    if [[ "$label" == "linux-armv7" ]]; then
      package_linux "$directory/$binary" "$label" arm7
    else
      package_linux "$directory/$binary" "$label" "$goarch"
    fi
  fi
}

build_target linux amd64 linux-amd64
build_target linux arm64 linux-arm64
build_target linux arm linux-armv7
build_target darwin amd64 darwin-amd64
build_target darwin arm64 darwin-arm64
build_target windows amd64 windows-amd64
build_target windows arm64 windows-arm64
cp "$ROOT_DIR/scripts/install-airlock-host.ps1" "$OUTPUT_DIR/install-airlock-host.ps1"

(
  cd "$OUTPUT_DIR"
  sha256sum ./*.deb ./*.rpm ./*.tar.gz ./*.zip ./install-airlock-host.ps1 > SHA256SUMS
)

"$ROOT_DIR/scripts/validate-release.sh" "$OUTPUT_DIR"
echo "built airlock-host $version release artifacts in $OUTPUT_DIR"
