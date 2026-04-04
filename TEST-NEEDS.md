# TEST-NEEDS.md — cloudguard-server

## CRG Grade: C — ACHIEVED 2026-04-04

## Current Test State

| Category | Count | Notes |
|----------|-------|-------|
| Test directories | 1 | Location(s): /tests |
| CI workflows | 20 | Running tests on GitHub Actions |
| Unit tests | Built-in | Rust/cargo test framework |
| Integration tests | Configured | Via integration/ directory |

## What's Covered

- [x] Rust unit test suite (cargo test)
- [x] Documentation tests
- [x] Example programs with tests

## Still Missing (for CRG B+)

- [ ] Code coverage reports (codecov integration)
- [ ] Detailed test documentation in CONTRIBUTING.md
- [ ] Integration tests beyond unit tests
- [ ] Performance benchmarking suite

## Run Tests

```bash
cargo test
```

## Session 9 additions (2026-04-04)

### What Was Added

| Area | Tests Added | Location |
|------|-------------|----------|
| E2E tests | 5 sections: cargo build, cargo test, live `/health` endpoint check, ABI/FFI Idris2 file structure, SPDX header coverage | `tests/e2e.sh` |
| CI runner | GitHub Actions workflow for E2E suite | `.github/workflows/e2e.yml` |

### Updated Test Counts

| Suite | Count | Status |
|-------|-------|--------|
| E2E (shell-based) | 5 test sections | All passing |
| CI workflows | 21 | Running tests on GitHub Actions |
