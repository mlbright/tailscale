# Tailscale Copilot Instructions

## Project Overview

Tailscale is a WireGuard-based mesh VPN. This repo contains the `tailscaled` daemon and `tailscale` CLI (module `tailscale.com`). Key architectural layers:

- **`ipn/ipnlocal/`** — Core node agent ("LocalBackend"), the central state machine (~8k lines in `local.go`)
- **`wgengine/`** — WireGuard engine; `magicsock/` handles NAT traversal
- **`control/controlclient/`** — Control plane connection (Noise protocol over HTTP)
- **`derp/`** — Relay servers for when direct connections fail
- **`tailcfg/`** — Protocol types shared between node and coordination server
- **`tsd/`** — `System` struct wiring all subsystems together (engine, netmon, router, DNS, state store)
- **`tsnet/`** — Library for embedding Tailscale in Go programs
- **`net/`** — Networking primitives: `tstun/`, `netmon/`, `portmapper/`, `dns/`, `stun/`, `packet/`

## Build & Test

Use `./tool/go` instead of bare `go` — it manages the pinned Go toolchain (currently 1.25.x):

```sh
./tool/go build ./cmd/tailscale ./cmd/tailscaled
./tool/go test ./ipn/ipnlocal/...
./tool/go vet ./...
```

For distribution builds with version info: `./build_dist.sh tailscale.com/cmd/tailscale`

Key Makefile targets: `make vet`, `make lint`, `make staticcheck`, `make generate`, `make check`

## File Conventions

**License header** — Every `.go`, `.ts`, `.tsx` file must start with (enforced by `license_test.go`):
```go
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
```

**Commit messages** — Go/Linux kernel style: `pkg/subpkg: imperative verb description` (no trailing period, lowercase after colon). See `docs/commit-messages.md`.

## Code Generation

Types with mutable fields get generated clone/view code. After modifying struct fields in packages like `tailcfg/`, `ipn/`, or `types/`:

1. Run `./tool/go generate ./path/to/package/...`
2. This regenerates `*_clone.go` (deep copy) and `*_view.go` (read-only accessors)
3. Clone files include compile-time assertions that break the build when fields change — if you see such errors, regenerate

View types use the `ж` field name (deliberately hard to type) to discourage direct access to the underlying mutable struct.

## Key Patterns

**Extensions** (`ipn/ipnext/`): New daemon features are added as extensions implementing `Extension` (Name/Init/Shutdown). Register via `RegisterExtension()` in `init()`. Extensions interact with `LocalBackend` only through the `Host` interface — never mutate state directly.

**Feature tags**: Features use `ts_omit_<name>` build tags to be excluded (see `feature/featuretags/`). The `cmd/featuretags` tool manages tag sets. When adding features, register them in the feature system.

**Eventbus** (`util/eventbus/`): Typed pub/sub with total ordering. Create a `Client`, then `Subscribe[T]`/`Publish[T]`. Used for decoupled communication between subsystems.

**Preferences** (`types/prefs/`): Use `prefs.Item[T]`, `prefs.List[T]`, `prefs.Map[K,V]` for user-facing settings. These integrate with the viewer/cloner codegen.

**Local API** (`ipn/localapi/`): HTTP endpoints under `/localapi/v0/`. Add new endpoints via `Register(name, handler)` in an `init()` block, typically gated by build feature flags.

**Synchronization**: Use `syncs.Mutex` (not `sync.Mutex`) for compatibility with the `checklocks` static analyzer. Use `syncs.AtomicValue[T]` and `syncs.MutexValue[T]` for generic thread-safe values.

**Health tracking** (`health/`): Report subsystem health via `Warnable` objects on the central `health.Tracker`.

**Environment knobs** (`envknob/`): Debug/dev settings via `envknob.RegisterBool("TS_FOO")` etc. Not a stable API. Use `TS_` prefix.

**Test utilities** (`tstest/`): Use `tstest.Replace()` for temporary value swaps, `tstest.WaitFor()` for polling assertions. Mark flaky tests with `flakytest.Mark(t, "URL")` — `cmd/testwrapper` auto-retries these.

## CI Checks

PRs must pass: `test.yml`, `vet.yml`, `golangci-lint.yml`, `checklocks.yml`. Integration tests (`ssh-integrationtest.yml`, `natlab-integrationtest.yml`) run separately. Run `make check` locally to catch common issues.
