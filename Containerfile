# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# Containerfile for cloudguard-server
# Build: podman build -t cloudguard-server:latest -f Containerfile .
# Run:   podman run --rm -e CLOUDFLARE_API_TOKEN=... -p 3847:3847 cloudguard-server:latest
# Seal:  selur seal cloudguard-server:latest

# --- Build stage ---
FROM cgr.dev/chainguard/wolfi-base:latest AS build

RUN apk add --no-cache rust cargo

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release

# --- Runtime stage ---
FROM cgr.dev/chainguard/static:latest

COPY --from=build /build/target/release/cloudguard-server /usr/local/bin/cloudguard-server

# Non-root user (chainguard images default to nonroot).
USER nonroot

EXPOSE 3847

ENTRYPOINT ["/usr/local/bin/cloudguard-server"]
