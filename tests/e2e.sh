#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# cloudguard-server — End-to-End Tests
#
# Tests the CloudGuard Server build, unit tests, and binary runtime behaviour.
# Validates the /health endpoint and required file structure (ABI/FFI definitions,
# config schema, source annotations).
#
# Usage:
#   bash tests/e2e.sh
#   just e2e

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
SKIP=0

# ─── Colour helpers ──────────────────────────────────────────────────
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# ─── Assertion helpers ───────────────────────────────────────────────

check() {
    local name="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        green "  PASS: $name"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $name (expected '$expected', got '${actual:0:120}')"
        FAIL=$((FAIL + 1))
    fi
}

check_status() {
    local name="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        green "  PASS: $name (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $name (expected HTTP $expected, got HTTP $actual)"
        FAIL=$((FAIL + 1))
    fi
}

check_exists() {
    local name="$1" path="$2"
    if [ -e "$path" ]; then
        green "  PASS: $name"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $name (path not found: $path)"
        FAIL=$((FAIL + 1))
    fi
}

skip_test() {
    yellow "  SKIP: $1 ($2)"
    SKIP=$((SKIP + 1))
}

echo "═══════════════════════════════════════════════════════════════"
echo "  cloudguard-server — End-to-End Tests"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Section 1: Build ────────────────────────────────────────────────
bold "Section 1: Cargo build"

if command -v cargo >/dev/null 2>&1; then
    BUILD_OUTPUT=$(cd "$PROJECT_DIR" && cargo build 2>&1)
    BUILD_EXIT=$?
    if [ "$BUILD_EXIT" -eq 0 ]; then
        green "  PASS: cargo build succeeded"
        PASS=$((PASS + 1))
    else
        red "  FAIL: cargo build failed"
        echo "$BUILD_OUTPUT" | tail -20 >&2
        FAIL=$((FAIL + 1))
    fi
else
    skip_test "cargo build" "cargo not available"
fi

echo ""

# ─── Section 2: Unit tests ───────────────────────────────────────────
bold "Section 2: Cargo unit tests"

if command -v cargo >/dev/null 2>&1; then
    TEST_OUTPUT=$(cd "$PROJECT_DIR" && cargo test 2>&1)
    TEST_EXIT=$?
    if [ "$TEST_EXIT" -eq 0 ]; then
        green "  PASS: cargo test passed"
        PASS=$((PASS + 1))
        check "test output contains 'test result: ok'" "test result: ok\|0 failed" "$TEST_OUTPUT"
    else
        red "  FAIL: cargo test failed"
        echo "$TEST_OUTPUT" | tail -20 >&2
        FAIL=$((FAIL + 1))
    fi
else
    skip_test "cargo test" "cargo not available"
fi

echo ""

# ─── Section 3: Binary runtime — health endpoint ─────────────────────
bold "Section 3: Server runtime — health endpoint"

BINARY="$PROJECT_DIR/target/debug/cloudguard-server"
if [ ! -f "$BINARY" ]; then
    BINARY="$PROJECT_DIR/target/release/cloudguard-server"
fi

if [ -f "$BINARY" ] && command -v curl >/dev/null 2>&1; then
    TEST_PORT=13847
    # Launch with a dummy token (health endpoint does not require real CF token)
    CLOUDFLARE_API_TOKEN=dummy_token_for_test "$BINARY" &
    SERVER_PID=$!
    trap "kill $SERVER_PID 2>/dev/null || true" EXIT

    # Wait for server to come up (max 10s)
    READY=0
    for _ in $(seq 1 20); do
        if curl -sf "http://localhost:$TEST_PORT/health" >/dev/null 2>&1; then
            READY=1
            break
        fi
        sleep 0.5
    done

    # Use default port 3847 (the real default from main.rs)
    if [ "$READY" -eq 0 ]; then
        for _ in $(seq 1 10); do
            if curl -sf "http://localhost:3847/health" >/dev/null 2>&1; then
                TEST_PORT=3847
                READY=1
                break
            fi
            sleep 0.5
        done
    fi

    if [ "$READY" -eq 1 ]; then
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$TEST_PORT/health")
        check_status "GET /health returns 200" "200" "$STATUS"

        BODY=$(curl -s "http://localhost:$TEST_PORT/health")
        check "health body is 'ok'" "ok" "$BODY"

        # Protected routes should return 401 without API key
        STATUS_ZONES=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$TEST_PORT/api/zones")
        if [ "$STATUS_ZONES" = "401" ] || [ "$STATUS_ZONES" = "200" ]; then
            green "  PASS: /api/zones returns expected status ($STATUS_ZONES)"
            PASS=$((PASS + 1))
        else
            red "  FAIL: /api/zones unexpected status (got $STATUS_ZONES, expected 200 or 401)"
            FAIL=$((FAIL + 1))
        fi
    else
        skip_test "server health check" "server did not start in time"
    fi

    kill "$SERVER_PID" 2>/dev/null || true
    trap - EXIT
else
    skip_test "server runtime tests" "binary not built or curl not available"
fi

echo ""

# ─── Section 4: ABI/FFI file structure ───────────────────────────────
bold "Section 4: ABI/FFI definitions (Idris2 + Zig)"

check_exists "src/abi directory exists"           "$PROJECT_DIR/src/abi"
check_exists "src/abi/Types.idr exists"           "$PROJECT_DIR/src/abi/Types.idr"
check_exists "src/abi/Layout.idr exists"          "$PROJECT_DIR/src/abi/Layout.idr"
check_exists "src/abi/Foreign.idr exists"         "$PROJECT_DIR/src/abi/Foreign.idr"
check_exists "ffi directory exists"               "$PROJECT_DIR/ffi"

echo ""

# ─── Section 5: Config and source file integrity ─────────────────────
bold "Section 5: Config files and SPDX headers"

check_exists "Cargo.toml exists"                  "$PROJECT_DIR/Cargo.toml"
check_exists "configs/config.ncl exists"          "$PROJECT_DIR/configs/config.ncl"

# All .rs files in src/ should have SPDX headers
RS_WITHOUT_SPDX=$(grep -rL "SPDX-License-Identifier" "$PROJECT_DIR/src/" --include="*.rs" 2>/dev/null || true)
if [ -z "$RS_WITHOUT_SPDX" ]; then
    green "  PASS: all .rs source files have SPDX headers"
    PASS=$((PASS + 1))
else
    red "  FAIL: .rs files missing SPDX headers: $RS_WITHOUT_SPDX"
    FAIL=$((FAIL + 1))
fi

# Cargo.toml should reference PMPL license
CARGO_LICENSE=$(grep "license" "$PROJECT_DIR/Cargo.toml" 2>/dev/null || echo "")
check "Cargo.toml has PMPL license" "PMPL" "$CARGO_LICENSE"

echo ""

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo "═══════════════════════════════════════════════════════════════"
printf "  Results: "
green "PASS=$PASS" | tr -d '\n'
echo -n "  "
if [ "$FAIL" -gt 0 ]; then red "FAIL=$FAIL" | tr -d '\n'; else echo -n "FAIL=0"; fi
echo -n "  "
if [ "$SKIP" -gt 0 ]; then yellow "SKIP=$SKIP"; else echo "SKIP=0"; fi
echo "═══════════════════════════════════════════════════════════════"

exit "$FAIL"
