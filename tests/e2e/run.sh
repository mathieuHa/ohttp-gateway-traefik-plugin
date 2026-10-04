#!/usr/bin/env bash
# Runs the end-to-end suite: downloads (and caches) a Traefik release binary,
# then runs the Go tests, which start Traefik with the repository loaded as a
# local plugin and talk to it through OHTTP clients.
#
# Dependencies: bash, curl, tar, go.
set -euo pipefail

TRAEFIK_VERSION="${TRAEFIK_VERSION:-v3.7.13}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="$HERE/.cache"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

bin="$CACHE_DIR/traefik-$TRAEFIK_VERSION"
if [[ ! -x "$bin" ]]; then
  mkdir -p "$CACHE_DIR"
  url="https://github.com/traefik/traefik/releases/download/${TRAEFIK_VERSION}/traefik_${TRAEFIK_VERSION}_${os}_${arch}.tar.gz"
  echo "Downloading $url"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -sSfL "$url" -o "$tmp/traefik.tar.gz"
  tar -xzf "$tmp/traefik.tar.gz" -C "$tmp" traefik
  mv "$tmp/traefik" "$bin"
  chmod +x "$bin"
fi

echo "Using $("$bin" version | head -1)"
cd "$HERE"
TRAEFIK_BIN="$bin" go test -count=1 -v "$@" ./...
