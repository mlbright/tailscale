#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# demo-vxlan-mirror.sh — Demonstrates the VXLAN packet mirror feature.
#
# This script:
#   1. Starts a local UDP listener that acts as a VXLAN collector.
#   2. Enables the VXLAN mirror via `tailscale debug vxlan-mirror`.
#   3. Generates some Tailscale traffic (a ping to self or a peer).
#   4. Shows the captured VXLAN-encapsulated WireGuard headers arriving
#      at the collector.
#   5. Toggles to full-packet mode, captures again, then stops the mirror.
#
# Prerequisites:
#   - tailscaled is running and the node is connected to a tailnet.
#   - `tailscale`, `socat` (or `nc`), and `xxd` are on $PATH.
#
# Usage:
#   ./scripts/demo-vxlan-mirror.sh [collector-port] [peer-ip]
#
# Examples:
#   ./scripts/demo-vxlan-mirror.sh              # uses defaults
#   ./scripts/demo-vxlan-mirror.sh 4789 100.64.0.2

set -euo pipefail

PORT="${1:-14789}"
PEER="${2:-}"
VNI=42
COLLECTOR_PID=""
CAPTURE_FILE=""

cleanup() {
  echo
  echo "=== Cleaning up ==="
  # Stop the mirror (ignore errors if already stopped).
  tailscale debug vxlan-mirror --stop 2>/dev/null || true
  # Kill the collector.
  if [[ -n "$COLLECTOR_PID" ]] && kill -0 "$COLLECTOR_PID" 2>/dev/null; then
    kill "$COLLECTOR_PID" 2>/dev/null || true
    wait "$COLLECTOR_PID" 2>/dev/null || true
  fi
  # Remove temp file.
  if [[ -n "$CAPTURE_FILE" ]]; then
    rm -f "$CAPTURE_FILE"
  fi
  echo "Done."
}
trap cleanup EXIT

# --- Resolve the tailscale binary ---
TAILSCALE="tailscale"
if ! command -v "$TAILSCALE" &>/dev/null; then
  echo "Error: 'tailscale' not found on PATH." >&2
  exit 1
fi

# --- Check prerequisites ---
for cmd in xxd; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: '$cmd' is required but not found on PATH." >&2
    exit 1
  fi
done

# --- Pick a peer to ping ---
if [[ -z "$PEER" ]]; then
  # Try to find our own Tailscale IP.
  PEER=$($TAILSCALE ip -4 2>/dev/null || true)
  if [[ -z "$PEER" ]]; then
    echo "Error: Could not determine a Tailscale IP. Pass a peer IP as the second argument." >&2
    exit 1
  fi
  echo "No peer IP specified; using self ($PEER)."
fi

echo "============================================="
echo " Tailscale VXLAN Packet Mirror Demo"
echo "============================================="
echo
echo "Collector port : $PORT"
echo "VNI            : $VNI"
echo "Peer to ping   : $PEER"
echo

# --- Step 1: Start a local VXLAN collector ---
echo "=== Step 1: Starting local VXLAN collector on UDP :$PORT ==="
CAPTURE_FILE=$(mktemp /tmp/vxlan-capture.XXXXXX)

# Use socat if available, otherwise fall back to nc.
if command -v socat &>/dev/null; then
  socat -u UDP-LISTEN:"$PORT",reuseaddr OPEN:"$CAPTURE_FILE",creat,trunc &
  COLLECTOR_PID=$!
elif command -v nc &>/dev/null; then
  # GNU netcat: -l -u -p PORT
  nc -l -u -p "$PORT" >"$CAPTURE_FILE" &
  COLLECTOR_PID=$!
else
  echo "Error: Neither 'socat' nor 'nc' found. Install one to act as the collector." >&2
  exit 1
fi
sleep 0.5
echo "Collector PID: $COLLECTOR_PID"
echo

# --- Step 2: Enable header-only mirror ---
echo "=== Step 2: Enabling VXLAN mirror (header-only mode) ==="
$TAILSCALE debug vxlan-mirror --dst "127.0.0.1:$PORT" --vni "$VNI"
echo

# --- Step 3: Generate traffic ---
echo "=== Step 3: Generating traffic (ping $PEER) ==="
$TAILSCALE ping --c 3 "$PEER" 2>/dev/null || echo "(ping completed or timed out)"
sleep 1
echo

# --- Step 4: Inspect captured packets ---
echo "=== Step 4: Inspecting captured VXLAN packets (header-only) ==="
if [[ -s "$CAPTURE_FILE" ]]; then
  BYTES=$(wc -c <"$CAPTURE_FILE")
  echo "Captured $BYTES bytes total."
  echo
  echo "First packet (hex dump, up to 80 bytes):"
  # Each mirrored packet is 8 (VXLAN) + up to 32 (WG header) = 40 bytes.
  xxd -l 80 "$CAPTURE_FILE"
  echo
  echo "VXLAN header breakdown (first packet):"
  FIRST_BYTE=$(xxd -p -l 1 "$CAPTURE_FILE")
  VNI_HEX=$(xxd -p -s 4 -l 3 "$CAPTURE_FILE")
  VNI_DEC=$((16#$VNI_HEX))
  echo "  Flags byte : 0x$FIRST_BYTE (0x08 = VNI present)"
  echo "  VNI        : 0x$VNI_HEX ($VNI_DEC)"
  echo
  echo "WireGuard header (bytes 8-11 = message type + receiver index):"
  xxd -s 8 -l 16 "$CAPTURE_FILE"
else
  echo "(No packets captured — this is expected if there is no active"
  echo " WireGuard tunnel to $PEER, e.g. when pinging self over loopback.)"
  echo " Try specifying a remote peer: ./scripts/demo-vxlan-mirror.sh $PORT <remote-tailscale-ip>"
fi
echo

# --- Step 5: Check status ---
echo "=== Step 5: Mirror status ==="
$TAILSCALE debug vxlan-mirror --status
echo

# --- Step 6: Switch to full-packet mode ---
echo "=== Step 6: Switching to full-packet mode ==="
# Truncate capture file for the next round.
: >"$CAPTURE_FILE"
$TAILSCALE debug vxlan-mirror --dst "127.0.0.1:$PORT" --vni "$VNI" --full
echo

echo "=== Generating more traffic ==="
$TAILSCALE ping --c 2 "$PEER" 2>/dev/null || echo "(ping completed or timed out)"
sleep 1

if [[ -s "$CAPTURE_FILE" ]]; then
  BYTES=$(wc -c <"$CAPTURE_FILE")
  echo "Full-packet mode captured $BYTES bytes total."
  echo
  echo "First packet (hex dump, up to 160 bytes):"
  xxd -l 160 "$CAPTURE_FILE"
else
  echo "(No packets captured in full-packet mode.)"
fi
echo

# --- Step 7: Stop ---
echo "=== Step 7: Stopping mirror ==="
$TAILSCALE debug vxlan-mirror --stop

echo
echo "=== Step 8: Verify stopped ==="
$TAILSCALE debug vxlan-mirror --status

echo
echo "============================================="
echo " Demo complete!"
echo "============================================="
echo
echo "Summary of CLI commands used:"
echo "  # Start (header-only, default — sends first 32 bytes of WG packet):"
echo "  tailscale debug vxlan-mirror --dst <host:port> --vni <vni>"
echo
echo "  # Start (full encrypted packet):"
echo "  tailscale debug vxlan-mirror --dst <host:port> --vni <vni> --full"
echo
echo "  # Check status:"
echo "  tailscale debug vxlan-mirror --status"
echo
echo "  # Stop:"
echo "  tailscale debug vxlan-mirror --stop"
