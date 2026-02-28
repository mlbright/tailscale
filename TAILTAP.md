# Tailtap: WireGuard Packet Mirroring via VXLAN

## Overview

The `tailtap` branch introduces **VXLAN-based packet mirroring** for
Tailscale's WireGuard data path. It allows a Tailscale node to replicate
outbound encrypted WireGuard packets — in real time — to a remote
collector over a standard VXLAN tunnel. The feature is designed to be
non-intrusive: it operates on the *encrypted* WireGuard ciphertext, never
on plaintext, and is off by default.

## What Changed

### New package: `feature/vxlanmirror/`

The core implementation lives in
[feature/vxlanmirror/vxlanmirror.go](feature/vxlanmirror/vxlanmirror.go).
Key components:

| Type / Function | Purpose |
|---|---|
| `Mirror` | Stateful object that owns a UDP socket to the collector. Safe for concurrent use. |
| `Mirror.SendBatch` | Hot-path entry point — called for every outbound WireGuard packet batch. |
| `Mirror.SendPacket` | Single-packet variant. |
| `wgCaptureLen` | Decides how much of each packet to mirror: handshake packets (types 1–3) are sent in full; transport data packets (type 4) are truncated to the 16-byte WireGuard header by default. |
| `writeVXLANHeader` | Writes the 8-byte VXLAN header (with VNI). |
| `writeInnerHeaders` / `writeInnerHeaders4` / `writeInnerHeaders6` | Builds synthetic Ethernet + IP + UDP headers inside the VXLAN frame so the collector sees a well-formed packet. Supports both IPv4 and IPv6 endpoints. |
| `Config` / `Status` | JSON-serializable types for the local API. |
| `serveLocalAPIDebugVXLANMirror` | Handles `GET` (status) and `POST` (configure) on `/localapi/v0/debug-vxlan-mirror`. |

The feature is registered via `feature.Register("vxlanmirror")` and the
local API endpoint via `localapi.Register(...)`, both in `init()`.

### New interface: `packet.PacketMirror` and `packet.MirrorCallback`

Defined in [net/packet/capture.go](net/packet/capture.go):

- **`MirrorCallback`** — `func(buffs [][]byte, offset int, src, dst netip.AddrPort)` — the
  function signature installed on the engine to receive each outbound
  encrypted batch.
- **`PacketMirror`** — the interface (`Start`, `Stop`, `Running`,
  `MirrorCallback`) that the `LocalBackend` uses to manage the mirror
  without depending on the concrete `vxlanmirror` package.

### Engine-level hook: `InstallMirrorHook`

A new method was added to the `Engine` interface in
[wgengine/wgengine.go](wgengine/wgengine.go), implemented by:

- **`magicsock.Conn`** — stores the callback in an `AtomicValue` and
  invokes it from two send paths:
  - `endpoint.send()` (peer-to-peer direct and relay) in
    [wgengine/magicsock/endpoint.go](wgengine/magicsock/endpoint.go) —
    called after the destination address is resolved.
  - `Conn.Send()` (lazy/DERP endpoint path) in
    [wgengine/magicsock/magicsock.go](wgengine/magicsock/magicsock.go).
- **`userspaceEngine`** — delegates to `magicConn.InstallMirrorHook()`
  in [wgengine/userspace.go](wgengine/userspace.go).
- **`watchdogEngine`** — pass-through in
  [wgengine/watchdog.go](wgengine/watchdog.go).

### LocalBackend integration

[ipn/ipnlocal/vxlanmirror.go](ipn/ipnlocal/vxlanmirror.go) adds four
methods to `LocalBackend`:

| Method | Role |
|---|---|
| `GetVXLANMirror()` | Returns the current `PacketMirror` (or nil). |
| `SetVXLANMirror(m)` | Registers the mirror implementation (called from `vxlanmirror` init). |
| `StartVXLANMirror(dst, vni, full)` | Starts mirroring and installs the engine hook. |
| `StopVXLANMirror()` | Stops mirroring and removes the engine hook. |

The `LocalBackend.Shutdown()` path in
[ipn/ipnlocal/local.go](ipn/ipnlocal/local.go) also cleanly tears down
the mirror if active.

### CLI command

[cmd/tailscale/cli/debug-vxlanmirror.go](cmd/tailscale/cli/debug-vxlanmirror.go)
adds `tailscale debug vxlan-mirror` with flags:

```
--dst    collector UDP address (host:port)
--vni    VXLAN Network Identifier (default 1)
--full   send full encrypted packet (default: header only)
--stop   stop mirroring
--status show mirror status
```

The command is gated behind the `ts_omit_vxlanmirror` build tag so it
can be excluded from production builds.

### Client library

[client/local/local.go](client/local/local.go) exposes
`GetVXLANMirrorStatus` and `SetVXLANMirror` for programmatic access from
Go callers (e.g. `tsnet` programs or management tools).

## How It Facilitates Observability

### 1. Passive, real-time traffic metadata capture

By mirroring the WireGuard transport headers (the first 16 bytes of
every type-4 packet), a collector receives a continuous stream of:

- **Receiver index** (4 bytes) — identifies the WireGuard session/peer.
- **Counter** (8 bytes) — a monotonically increasing nonce that reveals
  packet ordering, gaps (packet loss), and send rate.
- **Source and destination UDP endpoints** — encoded in the synthetic
  inner IP+UDP headers, showing which node pairs are communicating and
  over which paths (direct vs. DERP relay).

This is enough to build dashboards for **per-peer throughput, packet
loss, jitter, and session lifetime** — all without decrypting any
payload.

### 2. Full WireGuard handshake visibility

Handshake packets (Initiation, Response, Cookie Reply) are mirrored in
their entirety. These are already public-key-encrypted and contain no
user data, but they reveal:

- **Session establishment timing** — how long handshakes take, how often
  they rekey.
- **Handshake failures** — missing responses or excessive cookie replies
  indicate connectivity or DoS issues.
- **NAT traversal behavior** — endpoint changes between handshakes show
  NAT rebinding.

### 3. VXLAN encapsulation for standard tooling

Wrapping mirrored packets in VXLAN means the collector can be any
standard network monitoring stack:

- **Wireshark / tshark** — decodes VXLAN natively; inner
  Ethernet+IP+UDP+WireGuard layers are visible without custom dissectors.
- **Zeek / Suricata** — can process the VXLAN-decapsulated flow for IDS
  or network security monitoring.
- **Packet brokers (Gigamon, ntopng)** — VNI-based filtering lets you
  separate traffic from different nodes or environments.
- **Cloud VPC mirroring** — the format is compatible with AWS VPC
  Traffic Mirroring. Collectors already built for cloud environments work
  out of the box.

### 4. Minimal performance impact

- **Header-only mode** (default) copies only 16 bytes per data packet,
  plus ~50 bytes of VXLAN/IP/UDP framing — a fraction of the original
  packet size.
- The mirror callback is stored in an `AtomicValue` and checked with a
  nil-pointer fast path, adding near-zero overhead when mirroring is off.
- No allocations on the "mirror disabled" path — the check is a single
  atomic load.

### 5. Runtime control without restart

Mirroring can be toggled on or off at runtime via the local API or CLI
— no daemon restart required. This enables:

- **On-demand debugging** — enable mirroring only when investigating an
  issue, then disable it.
- **Dynamic collector rotation** — point mirroring at different
  collectors without downtime.
- **Full-packet mode escalation** — start with headers only and switch
  to full encrypted packets if deeper analysis is needed.

### 6. Security-preserving design

The mirrored data is the *encrypted* WireGuard ciphertext. Even in
full-packet mode, an observer at the collector sees only:

- Encrypted payloads (ChaCha20-Poly1305)
- WireGuard session metadata (receiver index, counter)
- Tunnel endpoint addresses

No plaintext user traffic is ever exposed. This makes `tailtap`
suitable for security-sensitive environments where regulatory or policy
constraints prohibit plaintext packet capture but allow encrypted
metadata collection.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────┐
│                   Tailscale Node                     │
│                                                      │
│  ┌──────────┐    ┌───────────┐    ┌───────────────┐  │
│  │ wgengine │───▶│ magicsock │───▶│  UDP / DERP   │──┼──▶ Peer
│  │          │    │           │    │  send path    │  │
│  └──────────┘    │           │    └───────┬───────┘  │
│                  │ mirrorHook│            │           │
│                  │ (atomic)  │◀───────────┘           │
│                  └─────┬─────┘                        │
│                        │ MirrorCallback               │
│                        ▼                              │
│               ┌────────────────┐                      │
│               │  vxlanmirror   │                      │
│               │    .Mirror     │                      │
│               │                │                      │
│               │ ┌────────────┐ │   VXLAN/UDP          │
│               │ │ SendBatch  │─┼──────────────────────┼──▶ Collector
│               │ └────────────┘ │                      │
│               └────────────────┘                      │
│                                                       │
│  Control: tailscale debug vxlan-mirror --dst ...      │
│           POST /localapi/v0/debug-vxlan-mirror        │
└──────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Start mirroring WireGuard headers to a collector
tailscale debug vxlan-mirror --dst 10.0.0.100:4789 --vni 1

# Check status
tailscale debug vxlan-mirror --status

# Switch to full encrypted packet mirroring
tailscale debug vxlan-mirror --dst 10.0.0.100:4789 --full

# Stop mirroring
tailscale debug vxlan-mirror --stop
```

On the collector side, capture with tcpdump or Wireshark:

```bash
# Capture VXLAN-encapsulated WireGuard packets
tcpdump -i eth0 -n udp port 4789 -w tailtap-capture.pcap
```
