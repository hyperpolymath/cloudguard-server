// SPDX-License-Identifier: PMPL-1.0-or-later

//! CloudGuard Server — REST + WebSocket API for Cloudflare domain security management.
//!
//! Provides a standalone HTTP API for CloudGuard operations, enabling:
//!   - External dashboards and monitoring tools to query domain compliance
//!   - CI/CD pipelines to audit/harden via HTTP instead of CLI
//!   - Real-time WebSocket progress updates for bulk operations
//!   - PanLL remote integration without Tauri
//!
//! Routes:
//!   GET  /health                        — health check (public, no auth)
//!   GET  /api/zones                     — list all zones
//!   GET  /api/zones/:id/settings        — get zone settings
//!   GET  /api/zones/:id/dns             — list DNS records
//!   POST /api/zones/:id/dns             — create DNS record
//!   DELETE /api/zones/:id/dns/:record   — delete DNS record
//!   POST /api/zones/:id/harden          — apply hardening
//!   POST /api/zones/:id/audit           — run compliance audit
//!   GET  /api/zones/:id/config          — download config snapshot
//!   GET  /api/zones/:id/config/diff     — diff live vs policy
//!   GET  /api/pages                     — list Pages projects
//!   POST /api/bulk/harden               — harden multiple zones
//!   GET  /ws/bulk                       — WebSocket for bulk operation progress
//!
//! Authentication: Set CLOUDGUARD_API_KEY env var to require X-API-Key header.

mod api;
mod auth;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post, delete},
    extract::{Path, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    Json,
};
use tower_http::cors::CorsLayer;

/// Shared application state containing the CF API token and optional API key.
struct AppState {
    token: String,
    /// If set, all /api/* and /ws/* routes require this key in X-API-Key header.
    api_key: Option<String>,
}

#[tokio::main]
async fn main() {
    let token = env::var("CLOUDFLARE_API_TOKEN").unwrap_or_else(|_| {
        eprintln!("Error: CLOUDFLARE_API_TOKEN not set");
        std::process::exit(1);
    });

    let api_key = env::var("CLOUDGUARD_API_KEY").ok();
    if api_key.is_none() {
        eprintln!("Warning: CLOUDGUARD_API_KEY not set — API endpoints are UNAUTHENTICATED");
    }

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3847);

    let state = Arc::new(AppState { token, api_key });

    // Protected routes — require API key when CLOUDGUARD_API_KEY is set.
    let protected = Router::new()
        // Zone operations
        .route("/api/zones", get(list_zones))
        .route("/api/zones/{id}/settings", get(get_zone_settings))
        .route("/api/zones/{id}/dns", get(list_dns_records).post(create_dns_record))
        .route("/api/zones/{id}/dns/{record_id}", delete(delete_dns_record))
        .route("/api/zones/{id}/harden", post(harden_zone))
        .route("/api/zones/{id}/audit", post(audit_zone))
        // Config sync
        .route("/api/zones/{id}/config", get(download_config))
        .route("/api/zones/{id}/config/diff", get(diff_config))
        // Pages
        .route("/api/pages", get(list_pages_projects))
        // Bulk operations
        .route("/api/bulk/harden", post(bulk_harden))
        // WebSocket for real-time progress
        .route("/ws/bulk", get(ws_bulk_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ));

    let app = Router::new()
        // Health check — always public
        .route("/health", get(health))
        .merge(protected)
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!("CloudGuard Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// Route handlers
// ============================================================================

/// Health check endpoint.
async fn health() -> &'static str {
    "ok"
}

/// List all zones in the Cloudflare account.
async fn list_zones(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.list_zones().await {
        Ok(zones) => Json(serde_json::json!({ "success": true, "result": zones })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Get settings for a specific zone.
async fn get_zone_settings(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.get_zone_settings(&zone_id).await {
        Ok(settings) => Json(serde_json::json!({ "success": true, "result": settings })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// List DNS records for a zone.
async fn list_dns_records(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.list_dns_records(&zone_id).await {
        Ok(records) => Json(serde_json::json!({ "success": true, "result": records })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Create a DNS record.
async fn create_dns_record(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.create_dns_record(&zone_id, &body).await {
        Ok(record) => Json(serde_json::json!({ "success": true, "result": record })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Delete a DNS record.
async fn delete_dns_record(
    State(state): State<Arc<AppState>>,
    Path((zone_id, record_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.delete_dns_record(&zone_id, &record_id).await {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Apply hardening settings to a zone.
async fn harden_zone(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.harden_zone(&zone_id).await {
        Ok(count) => Json(serde_json::json!({
            "success": true,
            "zone_id": zone_id,
            "settings_updated": count,
        })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Run a compliance audit on a zone's settings.
async fn audit_zone(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);

    let settings = match client.get_zone_settings(&zone_id).await {
        Ok(s) => s,
        Err(e) => return Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    };

    let (passed, failed, findings) = api::audit_settings(&settings);

    let total = passed + failed;
    let score = if total > 0 { (passed as f64) / (total as f64) * 100.0 } else { 100.0 };

    Json(serde_json::json!({
        "success": true,
        "zone_id": zone_id,
        "passed": passed,
        "failed": failed,
        "score": format!("{:.1}%", score),
        "findings": findings,
    })).into_response()
}

/// Download a full config snapshot for a zone (settings + DNS records as JSON).
async fn download_config(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.download_config(&zone_id).await {
        Ok(config) => Json(serde_json::json!({ "success": true, "result": config })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Diff live settings against the hardening policy.
async fn diff_config(
    State(state): State<Arc<AppState>>,
    Path(zone_id): Path<String>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.diff_config(&zone_id).await {
        Ok(diffs) => {
            let matching = diffs.iter().filter(|d| d.matches).count();
            let total = diffs.len();
            Json(serde_json::json!({
                "success": true,
                "zone_id": zone_id,
                "matching": matching,
                "total": total,
                "score": format!("{:.1}%", if total > 0 { matching as f64 / total as f64 * 100.0 } else { 100.0 }),
                "diffs": diffs,
            })).into_response()
        }
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// List Cloudflare Pages projects.
async fn list_pages_projects(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let client = api::AsyncCloudflareClient::new(&state.token);
    match client.list_pages_projects().await {
        Ok(projects) => Json(serde_json::json!({ "success": true, "result": projects })).into_response(),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e })).into_response(),
    }
}

/// Bulk harden multiple zones. Request body: { "zone_ids": ["id1", "id2", ...] }
async fn bulk_harden(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let zone_ids = body.get("zone_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();

    let client = api::AsyncCloudflareClient::new(&state.token);
    let mut results = Vec::new();

    for zone_id in &zone_ids {
        match client.harden_zone(zone_id).await {
            Ok(count) => results.push(serde_json::json!({
                "zone_id": zone_id,
                "status": "hardened",
                "settings_updated": count,
            })),
            Err(e) => results.push(serde_json::json!({
                "zone_id": zone_id,
                "status": "error",
                "error": e,
            })),
        }
    }

    Json(serde_json::json!({
        "success": true,
        "total": zone_ids.len(),
        "results": results,
    })).into_response()
}

/// WebSocket handler for real-time bulk operation progress.
async fn ws_bulk_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        // Send a welcome message
        let _ = socket.send(Message::Text(
            serde_json::json!({ "type": "connected", "message": "CloudGuard WebSocket ready" }).to_string().into()
        )).await;

        // Listen for commands (e.g. { "action": "harden", "zone_ids": [...] })
        while let Some(Ok(msg)) = socket.recv().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(cmd) = serde_json::from_str::<serde_json::Value>(&text) {
                        let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("");
                        match action {
                            "harden" => {
                                let zone_ids: Vec<String> = cmd.get("zone_ids")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                    .unwrap_or_default();

                                let total = zone_ids.len();
                                let client = api::AsyncCloudflareClient::new(&state.token);

                                for (i, zone_id) in zone_ids.iter().enumerate() {
                                    // Send progress update
                                    let _ = socket.send(Message::Text(
                                        serde_json::json!({
                                            "type": "progress",
                                            "completed": i,
                                            "total": total,
                                            "current_zone": zone_id,
                                        }).to_string().into()
                                    )).await;

                                    let status = match client.harden_zone(zone_id).await {
                                        Ok(count) => serde_json::json!({
                                            "type": "zone_complete",
                                            "zone_id": zone_id,
                                            "status": "hardened",
                                            "settings_updated": count,
                                        }),
                                        Err(e) => serde_json::json!({
                                            "type": "zone_error",
                                            "zone_id": zone_id,
                                            "error": e,
                                        }),
                                    };
                                    let _ = socket.send(Message::Text(status.to_string().into())).await;
                                }

                                // Send completion
                                let _ = socket.send(Message::Text(
                                    serde_json::json!({
                                        "type": "complete",
                                        "total": total,
                                    }).to_string().into()
                                )).await;
                            }
                            _ => {
                                let _ = socket.send(Message::Text(
                                    serde_json::json!({
                                        "type": "error",
                                        "message": format!("Unknown action: {}", action),
                                    }).to_string().into()
                                )).await;
                            }
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    })
}
