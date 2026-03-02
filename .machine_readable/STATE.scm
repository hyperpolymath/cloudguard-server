;; SPDX-License-Identifier: PMPL-1.0-or-later
;; CloudGuard Server — Project State

(state
  (metadata
    (version "0.1.0")
    (last-updated "2026-03-02")
    (author "Jonathan D.A. Jewell"))

  (project-context
    (name "cloudguard-server")
    (type "api-server")
    (purpose "REST + WebSocket API for Cloudflare domain security management")
    (language "rust")
    (framework "axum")
    (parent-module "panll/src/core/CloudGuard*"))

  (current-position
    (phase "initial-release")
    (completion-percentage 80)
    (milestone "v0.1.0 — Core API with zones, settings, DNS, audit, harden, WebSocket"))

  (route-to-mvp
    (done
      ("Axum server with CORS")
      ("Async CF API client with rate limiting")
      ("Zone listing endpoint")
      ("Settings read endpoint")
      ("DNS CRUD endpoints")
      ("Harden zone endpoint")
      ("Audit zone endpoint")
      ("Bulk harden endpoint")
      ("WebSocket real-time progress for bulk operations"))
    (remaining
      ("Config sync upload/download endpoints")
      ("Three-way diff endpoint")
      ("Pages project management endpoints")
      ("Authentication middleware (API key)")
      ("Containerfile for deployment")))

  (blockers-and-issues
    (none))

  (critical-next-actions
    ("Add API key authentication middleware")
    ("Implement config sync endpoints")
    ("Build and publish container image")))
