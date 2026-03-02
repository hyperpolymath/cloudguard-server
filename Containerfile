# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# Containerfile for cloudguard-server
# Build: podman build -t cloudguard_server:latest -f Containerfile .
# Run:   podman run --rm -it cloudguard_server:latest
# Seal:  selur seal cloudguard_server:latest

# --- Build stage ---
FROM cgr.dev/chainguard/wolfi-base:latest AS build

# TODO: Install build dependencies for your stack
# Examples:
#   RUN apk add --no-cache rust cargo       # Rust
#   RUN apk add --no-cache elixir erlang    # Elixir
#   RUN apk add --no-cache zig              # Zig

WORKDIR /build
COPY . .

# TODO: Replace with your build command
# Examples:
#   RUN cargo build --release
#   RUN mix deps.get && MIX_ENV=prod mix release
#   RUN zig build -Doptimize=ReleaseSafe

# --- Runtime stage ---
FROM cgr.dev/chainguard/static:latest

# Copy built artifact from build stage
# TODO: Replace with your binary/artifact path
# Examples:
#   COPY --from=build /build/target/release/cloudguard_server /usr/local/bin/
#   COPY --from=build /build/_build/prod/rel/cloudguard_server /app/
#   COPY --from=build /build/zig-out/bin/cloudguard_server /usr/local/bin/

# Non-root user (chainguard images default to nonroot)
USER nonroot

# TODO: Replace with your entrypoint
# ENTRYPOINT ["/usr/local/bin/cloudguard_server"]
