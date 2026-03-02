// SPDX-License-Identifier: PMPL-1.0-or-later

//! API key authentication middleware for CloudGuard Server.
//!
//! When `CLOUDGUARD_API_KEY` is set, all protected routes require an
//! `X-API-Key` header matching the configured key. If the env var is
//! not set, all requests pass through (unauthenticated mode with a
//! startup warning).

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::AppState;

/// Middleware that validates the `X-API-Key` header against the configured key.
///
/// If `AppState.api_key` is `None`, all requests pass through (no auth configured).
/// If set, the header must be present and match exactly (constant-time comparison).
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected_key) = &state.api_key else {
        // No API key configured — pass through.
        return next.run(request).await;
    };

    let provided = request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok());

    match provided {
        Some(key) if constant_time_eq(key.as_bytes(), expected_key.as_bytes()) => {
            next.run(request).await
        }
        Some(_) => {
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Invalid API key",
                })),
            )
                .into_response()
        }
        None => {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Missing X-API-Key header",
                })),
            )
                .into_response()
        }
    }
}

/// Constant-time byte comparison to prevent timing attacks on API key validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
