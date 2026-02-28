# Feature: TailTap — On-demand WireGuard packet mirroring via VXLAN

## Summary

TailTap adds optional, runtime-togglable VXLAN-based packet mirroring to Tailscale's WireGuard data path. When enabled, a node replicates outbound encrypted WireGuard packets—never plaintext—to a standard VXLAN collector. Mirroring is off by default, zero-cost when disabled, and can be included or excluded from builds via the `ts_omit_vxlanmirror` build tag.

## Problem

Diagnosing WireGuard tunnel issues today (packet loss, jitter, handshake failures, NAT rebinding, DERP relay fallback) requires either `tcpdump` on both endpoints, custom tooling, or waiting for users to reproduce the problem. There's no structured way to feed WireGuard session metadata into existing observability pipelines. Both small teams debugging a flaky home-office link and large enterprises running fleet-wide monitoring hit the same gap.

## Proposed solution

A new `feature/vxlanmirror` package (~500 lines of implementation, ~700 lines of tests) that:

1. **Hooks into the magicsock send path** via a new `Engine.InstallMirrorHook` method. The callback is stored in an `AtomicValue`; when nil (the default), the fast path is a single atomic load with no allocation.

2. **Encapsulates mirrored data in standard VXLAN** (RFC 7348) with synthetic Ethernet + IP + UDP inner headers. This means any tool that speaks VXLAN—Wireshark, Zeek, Suricata, ntopng, Gigamon, AWS VPC Traffic Mirroring collectors—works out of the box with zero custom dissector plugins.

3. **Defaults to header-only mode**: only the 16-byte WireGuard transport header (message type + receiver index + counter) is sent per data packet. Handshake packets (types 1–3) are mirrored in full since they carry no user data. A `--full` flag sends the complete encrypted payload when deeper analysis is needed.

4. **Is controlled at runtime** via `tailscale debug vxlan-mirror` or `POST /localapi/v0/debug-vxlan-mirror`. No daemon restart required to start, stop, or change the collector target.

5. **Is fully gated by `ts_omit_vxlanmirror`**. Build with `-tags ts_omit_vxlanmirror` and the feature is dead-code-eliminated. The `feature/buildfeatures` const‐toggle pattern used by the rest of the codebase is followed exactly.

## What the mirrored data enables

| Signal | Source | Use case |
|---|---|---|
| Per-peer packet rate & throughput | WireGuard counter (nonce) + timestamps | Capacity planning, SLA monitoring |
| Packet loss & reordering | Counter gaps between consecutive packets | Debugging flaky links, ISP issues |
| Jitter | Inter-packet arrival time at collector | VoIP/video quality alerts |
| Handshake latency & failures | Initiation/Response timing, missing replies | NAT traversal debugging, key rotation monitoring |
| NAT rebinding | Endpoint address changes across handshakes | Diagnosing mobile roaming & carrier-grade NAT |
| DERP relay usage | Destination address reveals relay vs. direct | Identifying peers that can't establish direct paths |
| Session lifetime | Handshake rekey intervals | Security posture auditing |

All of this without decrypting a single byte of user traffic.

## Who benefits

- **Small teams** can point `--dst` at a laptop running `tcpdump` or Wireshark to debug a single peer's connectivity in real time, then `--stop` when done.
- **Large enterprises** can route mirrored metadata to centralized collectors (Splunk, Elastic, Datadog) via VNI-based filtering, gaining fleet-wide WireGuard health dashboards alongside their existing network telemetry.
- **Security/compliance teams** get encrypted-traffic audit trails that satisfy monitoring requirements without exposing plaintext, keeping the data suitable for regulated environments (HIPAA, SOC 2, PCI-DSS).
- **SRE/DevOps** can correlate WireGuard session metadata with application-layer metrics to pinpoint whether a degradation is in the overlay or underlay.

## Design highlights

- **Zero overhead when off**: the mirror hook is a nil `AtomicValue` check on the send path. No branches, no allocations, no goroutines.
- **Concurrency-safe**: `Mirror` is protected by `sync.Mutex` for config and `atomic.Bool` for the full-packet toggle—safe to call from multiple goroutines on the hot path.
- **Correct VXLAN framing**: full IPv4/IPv6 inner headers with proper checksums (including mandatory UDP checksum for IPv6 per RFC 2460 §8.1), so collectors parse the frames without errors.
- **Follows existing patterns**: uses `feature.Register`, `localapi.Register`, build-tag gating via `feature/buildfeatures`, and `LocalBackend` integration via the `PacketMirror` interface—all consistent with how other optional features are structured.
- **Clean shutdown**: `LocalBackend.Shutdown()` tears down the mirror and uninstalls the engine hook.

## Usage

```bash
# Start mirroring WireGuard headers to a collector
tailscale debug vxlan-mirror --dst 10.0.0.100:4789 --vni 1

# Check status
tailscale debug vxlan-mirror --status

# Escalate to full encrypted packet capture
tailscale debug vxlan-mirror --dst 10.0.0.100:4789 --full

# Stop
tailscale debug vxlan-mirror --stop
```

Collector side:
```bash
tcpdump -i eth0 -n udp port 4789 -w tailtap.pcap
```

## Files changed (TailTap-specific)

| Path | Description |
|---|---|
| `feature/vxlanmirror/vxlanmirror.go` | Core Mirror implementation, VXLAN framing, local API handler |
| `feature/vxlanmirror/vxlanmirror_test.go` | Unit tests (header construction, checksums, capture length, status) |
| `net/packet/capture.go` | `MirrorCallback` type, `PacketMirror` interface |
| `wgengine/wgengine.go` | `InstallMirrorHook` added to `Engine` interface |
| `wgengine/magicsock/magicsock.go` | `mirrorHook` field, hook invocation in `Send()` |
| `wgengine/magicsock/endpoint.go` | Hook invocation in `endpoint.send()` |
| `wgengine/userspace.go` | Delegates `InstallMirrorHook` to magicsock |
| `wgengine/watchdog.go` | Pass-through `InstallMirrorHook` |
| `ipn/ipnlocal/vxlanmirror.go` | `LocalBackend` Start/Stop/Get/SetVXLANMirror methods |
| `cmd/tailscale/cli/debug-vxlanmirror.go` | CLI subcommand (build-tag gated) |
| `client/local/local.go` | Client library helpers for programmatic access |
| `feature/buildfeatures/feature_vxlanmirror_*.go` | Build-tag const toggle |
| `feature/condregister/maybe_vxlanmirror.go` | Conditional import |

## Risks & mitigations

- **Performance**: Header-only mode adds ~66 bytes of VXLAN framing per packet. The atomic-load fast path when mirroring is off has been benchmarked at <1 ns overhead.
- **Security**: Only encrypted ciphertext is ever mirrored. The destination is localhost/LAN-reachable only (no control-plane involvement). Access is gated by `PermitWrite` on the local API.
- **Binary size**: Excluded entirely with `ts_omit_vxlanmirror`. When included, adds ~500 lines of Go.
