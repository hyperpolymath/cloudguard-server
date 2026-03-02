// SPDX-License-Identifier: PMPL-1.0-or-later

//! Async Cloudflare API client for the CloudGuard server.
//!
//! Uses reqwest async (not blocking) since the server is tokio-based.
//! Provides the same operations as the CLI client but with async/await.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// Minimum interval between API requests to stay under CF rate limits.
const RATE_LIMIT_MS: u64 = 333;

/// CF API base URL.
const CF_API: &str = "https://api.cloudflare.com/client/v4";

// ============================================================================
// API response types
// ============================================================================

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[allow(dead_code)]
    errors: Vec<CfError>,
    result: Option<T>,
    result_info: Option<CfResultInfo>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    #[allow(dead_code)]
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CfResultInfo {
    #[allow(dead_code)]
    page: Option<u32>,
    #[allow(dead_code)]
    per_page: Option<u32>,
    #[allow(dead_code)]
    total_count: Option<u32>,
    total_pages: Option<u32>,
}

// ============================================================================
// Data types (serializable for API responses)
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub paused: bool,
    pub plan: CfPlan,
    #[serde(default)]
    pub name_servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfPlan {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfSetting {
    pub id: String,
    pub value: serde_json::Value,
    #[serde(default)]
    pub editable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfDnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    pub proxied: Option<bool>,
    pub priority: Option<u32>,
}

fn default_ttl() -> u32 { 1 }

/// Cloudflare Pages project metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CfPagesProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub production_branch: String,
}

/// One entry in a config diff (live vs policy comparison).
#[derive(Debug, Serialize)]
pub struct ConfigDiffEntry {
    pub setting_id: String,
    pub expected: String,
    pub actual: String,
    pub matches: bool,
}

/// Convert a serde_json::Value to a comparable string.
fn setting_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(v) => v.clone(),
        serde_json::Value::Bool(b) => if *b { "on".to_string() } else { "off".to_string() },
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

// ============================================================================
// Audit finding
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AuditFinding {
    pub setting_id: String,
    pub severity: String,
    pub expected: String,
    pub actual: String,
}

/// Hardening policy: (setting_id, expected_value, severity).
const HARDENING_POLICY: &[(&str, &str, &str)] = &[
    ("ssl", "full_strict", "CRITICAL"),
    ("min_tls_version", "1.2", "HIGH"),
    ("always_use_https", "on", "CRITICAL"),
    ("automatic_https_rewrites", "on", "MEDIUM"),
    ("opportunistic_encryption", "on", "LOW"),
    ("tls_1_3", "zrt", "MEDIUM"),
    ("browser_check", "on", "MEDIUM"),
    ("hotlink_protection", "on", "LOW"),
    ("email_obfuscation", "on", "LOW"),
    ("security_level", "medium", "MEDIUM"),
    ("brotli", "on", "LOW"),
    ("early_hints", "on", "LOW"),
    ("http3", "on", "LOW"),
    ("websockets", "on", "LOW"),
    ("opportunistic_onion", "on", "LOW"),
    ("ip_geolocation", "on", "LOW"),
];

// ============================================================================
// Async client
// ============================================================================

/// Async Cloudflare API client with rate limiting.
pub struct AsyncCloudflareClient {
    client: Client,
    token: String,
}

impl AsyncCloudflareClient {
    pub fn new(token: &str) -> Self {
        Self {
            client: Client::new(),
            token: token.to_string(),
        }
    }

    /// Rate-limited async GET.
    async fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        let body: serde_json::Value = resp.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(body)
    }

    /// Rate-limited async POST.
    async fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        let response_body: serde_json::Value = resp.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(response_body)
    }

    /// Rate-limited async PATCH.
    async fn patch(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.patch(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        let response_body: serde_json::Value = resp.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(response_body)
    }

    /// Rate-limited async DELETE.
    async fn delete_req(&self, path: &str) -> Result<(), String> {
        sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
        let url = format!("{}{}", CF_API, path);
        let resp = self.client.delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Delete failed: HTTP {}", resp.status()));
        }
        Ok(())
    }

    // ========================================================================
    // Zone operations
    // ========================================================================

    /// List all zones (auto-paginating).
    pub async fn list_zones(&self) -> Result<Vec<CfZone>, String> {
        let mut all_zones = Vec::new();
        let mut page = 1u32;

        loop {
            let body = self.get(&format!("/zones?page={}&per_page=50", page)).await?;
            let resp: CfResponse<Vec<CfZone>> = serde_json::from_value(body)
                .map_err(|e| format!("Parse error: {}", e))?;

            if let Some(zones) = resp.result {
                if zones.is_empty() { break; }
                all_zones.extend(zones);
            } else {
                break;
            }

            let total_pages = resp.result_info.and_then(|ri| ri.total_pages).unwrap_or(1);
            if page >= total_pages { break; }
            page += 1;
        }

        all_zones.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all_zones)
    }

    // ========================================================================
    // Settings operations
    // ========================================================================

    /// Get all settings for a zone.
    pub async fn get_zone_settings(&self, zone_id: &str) -> Result<Vec<CfSetting>, String> {
        let body = self.get(&format!("/zones/{}/settings", zone_id)).await?;
        let resp: CfResponse<Vec<CfSetting>> = serde_json::from_value(body)
            .map_err(|e| format!("Parse error: {}", e))?;
        resp.result.ok_or_else(|| "No settings in response".to_string())
    }

    /// Apply hardening settings to a zone. Returns number updated.
    pub async fn harden_zone(&self, zone_id: &str) -> Result<usize, String> {
        let settings = serde_json::json!({
            "items": [
                {"id": "ssl", "value": "full_strict"},
                {"id": "min_tls_version", "value": "1.2"},
                {"id": "always_use_https", "value": "on"},
                {"id": "automatic_https_rewrites", "value": "on"},
                {"id": "opportunistic_encryption", "value": "on"},
                {"id": "tls_1_3", "value": "zrt"},
                {"id": "security_header", "value": {
                    "strict_transport_security": {
                        "enabled": true,
                        "max_age": 31536000,
                        "include_subdomains": true,
                        "preload": true,
                        "nosniff": true,
                    }
                }},
                {"id": "browser_check", "value": "on"},
                {"id": "hotlink_protection", "value": "on"},
                {"id": "email_obfuscation", "value": "on"},
                {"id": "server_side_exclude", "value": "on"},
                {"id": "security_level", "value": "medium"},
                {"id": "brotli", "value": "on"},
                {"id": "early_hints", "value": "on"},
                {"id": "http3", "value": "on"},
                {"id": "0rtt", "value": "on"},
                {"id": "websockets", "value": "on"},
            ]
        });

        self.patch(&format!("/zones/{}/settings", zone_id), &settings).await?;
        Ok(17)
    }

    // ========================================================================
    // DNS operations
    // ========================================================================

    /// List DNS records for a zone (auto-paginating).
    pub async fn list_dns_records(&self, zone_id: &str) -> Result<Vec<CfDnsRecord>, String> {
        let mut all_records = Vec::new();
        let mut page = 1u32;

        loop {
            let body = self.get(&format!("/zones/{}/dns_records?page={}&per_page=100", zone_id, page)).await?;
            let resp: CfResponse<Vec<CfDnsRecord>> = serde_json::from_value(body)
                .map_err(|e| format!("Parse error: {}", e))?;

            if let Some(records) = resp.result {
                if records.is_empty() { break; }
                all_records.extend(records);
            } else {
                break;
            }

            let total_pages = resp.result_info.and_then(|ri| ri.total_pages).unwrap_or(1);
            if page >= total_pages { break; }
            page += 1;
        }

        Ok(all_records)
    }

    /// Create a DNS record.
    pub async fn create_dns_record(
        &self,
        zone_id: &str,
        body: &serde_json::Value,
    ) -> Result<CfDnsRecord, String> {
        let resp_body = self.post(&format!("/zones/{}/dns_records", zone_id), body).await?;
        let resp: CfResponse<CfDnsRecord> = serde_json::from_value(resp_body)
            .map_err(|e| format!("Parse error: {}", e))?;
        resp.result.ok_or_else(|| "No record in response".to_string())
    }

    /// Delete a DNS record.
    pub async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<(), String> {
        self.delete_req(&format!("/zones/{}/dns_records/{}", zone_id, record_id)).await
    }

    // ========================================================================
    // Config snapshot (download settings + DNS as a single JSON blob)
    // ========================================================================

    /// Download a full config snapshot for a zone (settings + DNS records).
    pub async fn download_config(&self, zone_id: &str) -> Result<serde_json::Value, String> {
        let settings = self.get_zone_settings(zone_id).await?;
        let dns_records = self.list_dns_records(zone_id).await?;

        Ok(serde_json::json!({
            "schema_version": 1,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "zone_id": zone_id,
            "settings": settings,
            "dns_records": dns_records,
        }))
    }

    /// Diff live settings against the hardening policy, returning per-setting comparison.
    pub async fn diff_config(&self, zone_id: &str) -> Result<Vec<ConfigDiffEntry>, String> {
        let settings = self.get_zone_settings(zone_id).await?;
        let mut diffs = Vec::new();

        for &(setting_id, expected, _severity) in HARDENING_POLICY {
            let setting = settings.iter().find(|s| s.id == setting_id);
            let actual = setting.map(|s| setting_value_to_string(&s.value))
                .unwrap_or_else(|| "<missing>".to_string());
            let matches = actual == expected;
            diffs.push(ConfigDiffEntry {
                setting_id: setting_id.to_string(),
                expected: expected.to_string(),
                actual,
                matches,
            });
        }

        Ok(diffs)
    }

    // ========================================================================
    // Pages project listing
    // ========================================================================

    /// List Cloudflare Pages projects for the account.
    pub async fn list_pages_projects(&self) -> Result<Vec<CfPagesProject>, String> {
        let body = self.get("/accounts/_/pages/projects").await;

        // The /accounts/_/ shorthand may not work; fall back to listing accounts first.
        match body {
            Ok(b) => {
                let resp: CfResponse<Vec<CfPagesProject>> = serde_json::from_value(b)
                    .map_err(|e| format!("Parse error: {}", e))?;
                Ok(resp.result.unwrap_or_default())
            }
            Err(_) => {
                // Try to find account ID from zones, then query pages.
                let zones = self.list_zones().await?;
                if zones.is_empty() {
                    return Ok(Vec::new());
                }
                // Get account ID from first zone.
                let zone_body = self.get(&format!("/zones/{}", zones[0].id)).await?;
                let account_id = zone_body
                    .get("result")
                    .and_then(|r| r.get("account"))
                    .and_then(|a| a.get("id"))
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| "Could not determine account ID".to_string())?;

                let pages_body = self.get(&format!("/accounts/{}/pages/projects", account_id)).await?;
                let resp: CfResponse<Vec<CfPagesProject>> = serde_json::from_value(pages_body)
                    .map_err(|e| format!("Parse error: {}", e))?;
                Ok(resp.result.unwrap_or_default())
            }
        }
    }
}

// ============================================================================
// Audit logic
// ============================================================================

/// Audit settings against the hardening policy.
pub fn audit_settings(settings: &[CfSetting]) -> (usize, usize, Vec<AuditFinding>) {
    let mut passed = 0;
    let mut failed = 0;
    let mut findings = Vec::new();

    for &(setting_id, expected, severity) in HARDENING_POLICY {
        let setting = settings.iter().find(|s| s.id == setting_id);
        match setting {
            Some(s) => {
                let actual = match &s.value {
                    serde_json::Value::String(v) => v.clone(),
                    serde_json::Value::Bool(b) => if *b { "on".to_string() } else { "off".to_string() },
                    serde_json::Value::Number(n) => n.to_string(),
                    other => other.to_string(),
                };

                if actual == expected {
                    passed += 1;
                } else {
                    failed += 1;
                    findings.push(AuditFinding {
                        setting_id: setting_id.to_string(),
                        severity: severity.to_string(),
                        expected: expected.to_string(),
                        actual,
                    });
                }
            }
            None => {
                failed += 1;
                findings.push(AuditFinding {
                    setting_id: setting_id.to_string(),
                    severity: severity.to_string(),
                    expected: expected.to_string(),
                    actual: "<missing>".to_string(),
                });
            }
        }
    }

    (passed, failed, findings)
}
