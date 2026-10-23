# 7. Declared MSRV floor decoupled from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` + `CLAUDE.core.md`, "Rust MSRV &
Toolchain Policy") separates two distinct things: the **dev toolchain**, pinned to
the current stable across the whole fleet in `rust-toolchain.toml`, and the
**declared MSRV** (`rust-version`), a downstream-facing compatibility promise.
Although this fork does not publish its crates under the upstream crates.io names,
third parties may still build or depend on the source, so its MSRV remains a
compatibility feature rather than a development convenience.

Evidence: `rust-toolchain.toml` pins `channel = "1.96.0"` (dev/CI build toolchain);
workspace `Cargo.toml` `[workspace.package] rust-version = "1.85"` (declared floor,
inherited by both members); the README `Rust 1.85+` badge.

## Decision

1. **Develop and gate on the pinned stable (1.96.0)** via `rust-toolchain.toml`,
   ending "which Rust am I on" drift and fmt/clippy churn fleet-wide.
2. **Declare `rust-version = "1.85"`** as the promised floor, hoisted once in
   `[workspace.package]` (DRY) and inherited by `amcache-core` and
   `amcache-forensic`. The two numbers are deliberately different: 1.96 is what we
   build with, 1.85 is what a consumer needs.
3. **Do not raise the floor to match the toolchain.** Raising a library's MSRV
   narrows who can reuse it and is treated as a compatibility change; 1.85 is
   bumped only if the code genuinely needs a newer-Rust feature (the floor already
   reflects what the dependency graph — winreg-core, forensicnomicon, edition
   2021 — requires).

## Consequences

- Contributors and CI share one toolchain; downstream consumers get a stated,
  lower floor.
- A future toolchain bump is a one-line `rust-toolchain.toml` change and does not
  touch the promised MSRV.

## Verification

The 1.85 floor is declared in `Cargo.toml` and verified by CI's dedicated MSRV
job. The remaining build, lint, documentation, and test jobs use the pinned 1.96
development toolchain.
