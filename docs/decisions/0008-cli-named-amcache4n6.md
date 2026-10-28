# 8. The examiner-facing CLI is named amcache4n6 (full artifact name)

Date: 2026-07-24
Status: Superseded (2026-10-28)

Fork note (2026-10-28): Yamato Security names every parser's command after its repository, so the
command is now `ys-amcache-parser`. The record below is upstream's decision, kept as it was.

Fork note (2026-10-24): Yamato Security retains the `amcache4n6` command for compatibility. The
fork's crates are versioned 0.2.0, are not published under the upstream crates.io names, and are
built from source. Structured output options extend the CLI without changing this naming decision.

## Context

The original fleet naming grammar (`ronin-issen/CLAUDE.md`, "Crate naming grammar" +
"Release & Distribution Standard") gives front-end binaries the `<x>4n6`
convention (br4n6, ev4n6, sqlite4n6, mem4n6, disk4n6). The binary is the surface an
examiner actually runs — the upstream `cargo install amcache-forensic` originally put it on
`$PATH` — so
its name must be self-describing and unambiguous when typed at a shell, stripped of
all repo context.

The CLI was first shipped as `amc4n6` (commit `ca381e8`) and then deliberately
renamed to `amcache4n6` (commit `048c14d`, "rename amc4n6 CLI to amcache4n6
(full-artifact-name convention)"). The short form `amc` is an opaque abbreviation
that reads as neither the artifact nor a recognizable tool; the full artifact name
is instantly legible.

Historical evidence: `forensic/src/bin/amcache4n6.rs`; `forensic/Cargo.toml`
`categories = ["command-line-utilities", …]`; the upstream README "Run it" section; the
git-tracked rename `forensic/src/bin/{amc4n6.rs => amcache4n6.rs}`.

## Decision

1. **Binary = `amcache4n6`** — the full, unabbreviated artifact name plus the `4n6`
   convention, chosen over the initial cryptic `amc4n6`.
2. **The CLI is a thin shell over the libraries** — it reads the file and renders;
   all decoding and analysis live in `amcache_core`/`amcache_forensic` (Humble
   Object). A positional hive path, record selectors, output format, and output destination are
   handled by the shell; serializers remain in the reusable forensic library.
3. **Exit codes are honest**: `2` for a usage error (no path), `FAILURE` for an I/O
   or parse error (with the offending path and error surfaced), `SUCCESS`
   otherwise — so the tool composes in scripts and never masks a failure as success.

## Consequences

- The fork keeps the clearly named `amcache4n6` binary while avoiding publication under the
  upstream-owned crate names.
- Because logic sits in the libraries, the binary stays a small, testable render
  shell and the same analysis is reusable by Issen/disk4n6 without the CLI.
- The rename happened before first crates.io publish, so no released binary name
  was broken.
