#!/usr/bin/env bash
#
# lettre/mayhem/test.sh — RUN lettre's own functional test suite for the FUZZED code and emit a
# CTRF summary. exit 0 iff no test failed. This script only RUNS the suite (via `cargo test
# --lib`); it never builds it — mayhem/build.sh precompiled it with `--no-run` in a separate,
# non-sanitized build.
#
# PATCH-grade oracle. The 166 `#[test]` functions embedded in src/ (mailbox/types.rs,
# header/{content_type,content_disposition,date,mailbox,textual,special,content}.rs,
# address/types.rs, message/{mod,mimebody,body,attachment,dkim}.rs, plus the smtp-transport unit
# tests that don't dial a live server) assert EXACT parsed/encoded values against lettre's public
# API — this is the same surface mayhem_mailbox_parse and mayhem_message_build fuzz. A no-op /
# "return Ok(...)" / output-altering patch to the mailbox parser, address validator, or body
# encoder fails here, same as it fails the fuzz harnesses' own inline asserts. The produced test
# binary is a normal dynamically-linked glibc executable (Rust's default on this target — no
# cgo-style trick needed, unlike Go), so it is fully reachable by verify-repo's LD_PRELOAD
# sabotage shim.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not available — cannot run the test suite" >&2
  emit_ctrf "cargo-test" 0 1 0; exit 2
fi

echo "=== running cargo test --lib (precompiled by build.sh --no-run) ==="
# Same feature set build.sh precompiled with. Use the image's DEFAULT toolchain (same nightly the
# fuzz build uses), so no `+toolchain` override. RUSTFLAGS cleared so it inherits nothing from the
# sanitizer build.
TEST_FEATURES="builder,file-transport,file-transport-envelope,mime03,hostname,smtp-transport,sendmail-transport,pool,dkim,rustls,ring,webpki-roots"
out="$(RUSTFLAGS="" cargo test --no-default-features --features "$TEST_FEATURES" --lib --no-fail-fast --jobs "$MAYHEM_JOBS" 2>&1)"; rc=$?
echo "$out"

# libtest prints one line per test binary:
#   test result: ok. 137 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
PASSED=0; FAILED=0; IGNORED=0
while read -r p f i; do
  PASSED=$(( PASSED + p )); FAILED=$(( FAILED + f )); IGNORED=$(( IGNORED + i ))
done < <(printf '%s\n' "$out" \
  | sed -n 's/^test result:.* \([0-9][0-9]*\) passed; \([0-9][0-9]*\) failed; \([0-9][0-9]*\) ignored.*/\1 \2 \3/p')

# If we parsed no result lines, fall back to the cargo exit code (e.g. compile error).
if [ "$(( PASSED + FAILED + IGNORED ))" -eq 0 ]; then
  echo "could not parse any 'test result:' lines; using cargo exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "cargo-test" 1 0 0; exit 0; }
  emit_ctrf "cargo-test" 0 1 0; exit 1
fi

emit_ctrf "cargo-test" "$PASSED" "$FAILED" "$IGNORED"
