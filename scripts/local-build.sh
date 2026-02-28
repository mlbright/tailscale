#!/usr/bin/env bash
#
# local-build.sh — Build tailscale and tailscaled binaries locally
# using the project's pinned Go toolchain.
#
# Usage:
#   ./local-build.sh              # build both tailscale + tailscaled
#   ./local-build.sh tailscale    # build only the CLI
#   ./local-build.sh tailscaled   # build only the daemon
#   ./local-build.sh --dist       # distribution build with version info
#   ./local-build.sh --check      # build + vet + staticcheck
#
# Binaries are placed in ./build/ by default (override with $OUTDIR).

set -euo pipefail

cd "$(dirname "$0")"

GO="../tool/go"
OUTDIR="${OUTDIR:-./build}"

mkdir -p "$OUTDIR"

build_binary() {
  local pkg="$1"
  local name
  name="$(basename "$pkg")"
  echo "==> Building $name ..."
  $GO build -o "$OUTDIR/$name" "tailscale.com/cmd/$name"
  echo "    $OUTDIR/$name"
}

build_dist() {
  echo "==> Distribution build (with version info) ..."
  TS_USE_TOOLCHAIN=1 ./build_dist.sh -o "$OUTDIR/tailscale" tailscale.com/cmd/tailscale
  TS_USE_TOOLCHAIN=1 ./build_dist.sh -o "$OUTDIR/tailscaled" tailscale.com/cmd/tailscaled
}

run_checks() {
  echo "==> Running go vet ..."
  $GO vet ./...
  echo "==> Running staticcheck ..."
  $GO run honnef.co/go/tools/cmd/staticcheck -- "$($GO run ./tool/listpkgs --ignore-3p ./...)"
}

# --- main ---

if [ $# -eq 0 ]; then
  build_binary tailscale
  build_binary tailscaled
  echo ""
  echo "Done. Binaries are in $OUTDIR/"
  exit 0
fi

case "$1" in
tailscale)
  build_binary tailscale
  ;;
tailscaled)
  build_binary tailscaled
  ;;
--dist)
  build_dist
  ;;
--check)
  build_binary tailscale
  build_binary tailscaled
  run_checks
  ;;
--help | -h)
  head -14 "$0" | tail -11
  exit 0
  ;;
*)
  echo "Unknown argument: $1" >&2
  echo "Run '$0 --help' for usage." >&2
  exit 1
  ;;
esac

echo ""
echo "Done. Binaries are in $OUTDIR/"
