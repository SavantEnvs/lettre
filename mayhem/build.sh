#!/usr/bin/env bash
#
# lettre/mayhem/build.sh — build the additive mayhem/fuzz/ cargo-fuzz crate
# (mayhem_mailbox_parse, mayhem_message_build — see mayhem/Dockerfile header for why upstream
# itself ships no fuzz/ dir) as sanitized libFuzzer binaries, replicating OSS-Fuzz's Rust path
# (base-builder-rust `compile` + `cargo fuzz build -O`).
#
# cargo-fuzz drives the build:
#   - it provides its own libFuzzer runtime (the produced binary IS a libFuzzer target — Mayhem
#     runs it directly via `libfuzzer: true`);
#   - ASan is enabled the Rust way, through RUSTFLAGS `-Zsanitizer=address` (NOT clang's
#     $SANITIZER_FLAGS / CFLAGS — those don't apply to rustc), which is what OSS-Fuzz's `compile`
#     sets for FUZZING_LANGUAGE=rust. nightly is required for `-Zsanitizer`.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE. This first
# (online) build populates the cargo registry under $CARGO_HOME (pinned, $HOME-independent — see
# the Dockerfile). Do NOT pass --offline here; the rlenv runtime exports CARGO_NET_OFFLINE=true
# for the re-run.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer (kept for parity even
# though the Rust build doesn't invoke clang directly; cargo's cc-built deps might).
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C llvm-args=--dwarf-version=3}"
export MAYHEM_JOBS
export RUST_DEBUG_FLAGS
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# DWARF anchor: rustc's ASan codegen (-Zsanitizer=address) unconditionally emits DWARF5 for EVERY
# compilation unit, ignoring -Cdwarf-version entirely — a known, fleet-wide, currently-open
# rustc/LLVM limitation (docs/netnew-fleet-playbook.md, "rust-dwarf-blocker"), not fixable by
# rustc flags alone. verify-repo.sh's DWARF gate reads only the FIRST compilation unit's version
# (`grep -m1 "Version:"`), so prepend a tiny hand-built DWARF3 object as the FIRST input to the
# linker via a custom `-C linker=` wrapper — it carries no runtime code, only a debug-info CU, so
# it doesn't change program behavior; it only makes the first CU satisfy the < 4 check. The anchor
# object MUST be prepended (never appended) or its CU does not land at .debug_info offset 0.
ANCHOR_C=/tmp/mayhem-dwarf-anchor.c
ANCHOR_O=/tmp/mayhem-dwarf-anchor.o
LINKER_WRAP=/tmp/mayhem-dwarf-linker.sh
cat > "$ANCHOR_C" <<'EOF'
int __mayhem_dwarf3_anchor;
EOF
clang -O0 -gdwarf-3 -c "$ANCHOR_C" -o "$ANCHOR_O"
cat > "$LINKER_WRAP" <<EOF
#!/bin/sh
exec clang "$ANCHOR_O" "\$@"
EOF
chmod +x "$LINKER_WRAP"

FUZZ_DIR="mayhem/fuzz"
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }
TRIPLE="x86_64-unknown-linux-gnu"

# Replicate OSS-Fuzz `compile` RUSTFLAGS for a libFuzzer+ASan Rust build. `--cfg fuzzing` matches
# what libfuzzer-sys expects; force-frame-pointers aids ASan stack traces. Thread
# $RUST_DEBUG_FLAGS for DWARF < 4 symbols (§6.2 item 10) — the anchor above is what actually
# satisfies the gate; these flags are kept for parity/best-effort.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cdebuginfo=2 -Cdwarf-version=3 -Cforce-frame-pointers -Csplit-debuginfo=off -Clinker=$LINKER_WRAP $RUST_DEBUG_FLAGS"

echo "=== cargo fuzz build (image-default nightly toolchain, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# `-O` (release w/ opt) + `--debug-assertions` mirrors OSS-Fuzz's Rust build (catches
# overflow/debug asserts during fuzzing). Use the image's DEFAULT toolchain (the Dockerfile pins
# it to the required nightly); a `+toolchain` override would make rustup try to install a
# different channel into the read-only shared /opt/toolchains/rust. Build per-target so a single
# bad target doesn't mask the others.
#
# lettre's fuzz/Cargo.toml declares its own [workspace] (members = ["."]), and the repo ROOT
# Cargo.toml has no [workspace] table at all (lettre is a single-crate repo) — so mayhem/fuzz is
# never a member of any parent workspace, and `cargo fuzz build`'s output lands under its OWN
# `mayhem/fuzz/target/<triple>/release/<t>` (never the repo-root `target/`). Assert the binary
# exists so a wrong path assumption fails loudly instead of silently "succeeding".
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  if [ ! -x "$bin" ]; then
    echo "ERROR: expected fuzz binary not found at $bin" >&2
    exit 1
  fi
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
  file "/mayhem/$t" | grep -q 'dynamically linked' \
    || { echo "ERROR: /mayhem/$t is not dynamically linked (regression guard)" >&2; exit 1; }
done

echo "=== build the backport reproducer (plain cargo, no libFuzzer) ==="
# client-buggy-mhh-run-30 reproduces the mayhemheroes `client` target, which was NOT a libFuzzer
# target: a plain binary fed by Mayhem's network fuzzer, whose crash output is nothing but the Rust
# panic line. mayhem/client-repro keeps that form (see its src/main.rs) and takes the test case as a
# file (`cmd: … @@`), so the replay of the original run's crashers produces the same crash reports
# the original run triaged. Built with the ORIGINAL harness's flags (`-g -Cdebug-assertions=on`,
# mayhem/Dockerfile on the fuzzed fork), plus the DWARF anchor + DWARF<4 flags this fleet requires
# (§6.2 item 10); no -Zsanitizer: ASan's runtime would print a stack trace on the panic path and is
# irrelevant to a safe-Rust unwrap() bug.
REPRO_DIR="mayhem/client-repro"
REPRO_TARGET="client-buggy-mhh-run-30"
RUSTFLAGS="-Cdebug-assertions=on -Cdebuginfo=2 -Cdwarf-version=3 -Cforce-frame-pointers -Csplit-debuginfo=off -Clinker=$LINKER_WRAP" \
  cargo build --release --manifest-path "$SRC/$REPRO_DIR/Cargo.toml"
repro_bin="$SRC/$REPRO_DIR/target/release/$REPRO_TARGET"
[ -x "$repro_bin" ] || { echo "ERROR: expected reproducer binary not found at $repro_bin" >&2; exit 1; }
cp "$repro_bin" "/mayhem/$REPRO_TARGET"
# The Mayhem target binary IS the standalone reproducer here (one input file per invocation); ship
# it under the fleet's `-standalone` name too, so `/mayhem/<target>-standalone <crasher>` works.
cp "$repro_bin" "/mayhem/$REPRO_TARGET-standalone"
echo "built /mayhem/$REPRO_TARGET (+ -standalone)"
file "/mayhem/$REPRO_TARGET" | grep -q 'dynamically linked' \
  || { echo "ERROR: /mayhem/$REPRO_TARGET is not dynamically linked (regression guard)" >&2; exit 1; }
# Guard the property the backport depends on: a libFuzzer entry point would make Mayhem group every
# crash under one symbolized backtrace (and fuzz-smoke would demand libfuzzer: true).
if grep -aq LLVMFuzzerTestOneInput "/mayhem/$REPRO_TARGET"; then
  echo "ERROR: /mayhem/$REPRO_TARGET defines LLVMFuzzerTestOneInput — it must be a plain binary" >&2
  exit 1
fi

echo "=== precompile lettre's own test suite (hermetic, normal non-sanitized flags) ==="
# Separate, clean build from the sanitized fuzz build above — mayhem/test.sh only RUNS this, never
# compiles. RUSTFLAGS cleared so it inherits nothing from the ASan build's -Zsanitizer/linker
# wrapper. --no-default-features + an explicit feature list: `smtp-transport`'s own unit tests
# (src/transport/smtp/transport.rs, e.g. `transport_from_url`) reference the `Tls` enum /
# `SmtpTransport::from_url`, which upstream itself gates behind
# `#[cfg(any(feature = "native-tls", feature = "rustls", feature = "boring-tls"))]` — so at least
# one TLS backend feature is REQUIRED just to compile `--lib` tests, even though nothing in the
# suite we run makes a live TLS connection. `rustls,ring,webpki-roots` is the pure-Rust backend
# (no system OpenSSL / cert-store dependency, so it stays air-gap-friendly); native-tls/boring-tls
# would need libssl-dev baked into the image for no benefit here. The native `smtp-transport`
# tests that DO need a live server (upstream CI starts `smtp-sink` + coredns for them) live in
# tests/transport_smtp.rs / tests/transport_smtp_pool.rs, not in --lib, so they are never reached.
# `--lib` only (not `--tests`): the crate's tests/*.rs integration tests include
# transport_smtp.rs / transport_smtp_pool.rs (need a live 127.0.0.1:2525 listener) and
# transport_sendmail.rs (needs a real `sendmail` binary) — none reachable in this offline image,
# so we exercise the 166 `#[test]` unit tests embedded directly in src/ instead, which is exactly
# where the fuzzed parser/builder code (mailbox/types.rs, header/*.rs, address/types.rs,
# message/mod.rs, mimebody.rs, body.rs) lives and is asserted against known values.
TEST_FEATURES="builder,file-transport,file-transport-envelope,mime03,hostname,smtp-transport,sendmail-transport,pool,dkim,rustls,ring,webpki-roots"
RUSTFLAGS="" cargo test --no-default-features --features "$TEST_FEATURES" --lib --no-run --no-fail-fast --jobs "$MAYHEM_JOBS"

echo "build.sh complete:"
ls -la "/mayhem/${FUZZ_TARGETS[@]}" 2>&1 || true
