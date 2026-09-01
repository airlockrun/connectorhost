#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/dist}"

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
    archive="$OUTPUT_DIR/airlock-host-$version-$label.zip"
    (cd "$directory" && zip -q -9 "$archive" "$binary")
  else
    archive="$OUTPUT_DIR/airlock-host-$version-$label.tar.gz"
    tar -C "$OUTPUT_DIR" -czf "$archive" "$(basename "$directory")"
  fi
}

build_target linux amd64 linux-amd64
build_target linux arm64 linux-arm64
build_target linux arm linux-armv7
build_target darwin amd64 darwin-amd64
build_target darwin arm64 darwin-arm64
build_target windows amd64 windows-amd64
build_target windows arm64 windows-arm64

(
  cd "$OUTPUT_DIR"
  sha256sum ./*.tar.gz ./*.zip > SHA256SUMS
)

echo "built airlock-host $version archives in $OUTPUT_DIR"
