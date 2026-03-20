#[allow(dead_code)]
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::time::Duration;

/// Build a pre-configured HTTP client.
pub fn build_client(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none()) // no redirect — prevents OAuth 302 FP
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) CatchClaw/5.0")
        .build()
        .expect("failed to build HTTP client")
}

/// Standard auth + JSON headers.
pub fn auth_headers(token: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("Content-Type".into(), "application/json".into());
    if !token.is_empty() {
        h.insert("Authorization".into(), format!("Bearer {token}"));
    }
    h
}

// ---------------------------------------------------------------------------
// False-positive ​filters (ported from Go)
// ---------------------------------------------------------------------------

/// Detect OpenClaw challenge-response handshake pages.
pub fn is_challenge_response(body: &str) -> bool {
    let markers = [
        "connect.challenge",
        "\"type\":\"challenge\"",
        "challenge-response",
        "x-challenge-token",
    ];
    let lower = body.to_lowercase();
    markers.iter().any(|m| lower.contains(m))
}

/// Detect non-API responses (HTML/SPA fallback).
pub fn is_non_api_response(body: &str, content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        if ct.contains("text/html") && body.contains("<!DOCTYPE") {
            return true;
        }
    }
    is_spa_fallback(body)
}

/// Detect nginx SPA fallback.
fn is_spa_fallback(body: &str) -> bool {
    let markers = ["<app-root>", "<div id=\"app\"", "__NEXT_DATA__", "window.__NUXT__"];
    markers.iter().any(|m| body.contains(m))
}

/// Check if HTTP response is a real success (not challenge/SPA).
#[allow(dead_code)]
pub fn is_real_success(status: StatusCode, body: &str, content_type: Option<&str>) -> bool {
    status.is_success() && !is_challenge_response(body) && !is_non_api_response(body, content_type)
}

/// Common refusal phrases for LLM-based exploit detection.
pub const REFUSAL_PHRASES: &[&str] = &[
    "i cannot", "i can't", "i'm not able", "i am not able",
    "i must decline", "i'm unable", "as an ai",
    "i don't have the ability", "not possible for me",
    "i apologize", "i'm sorry, but", "against my programming",
    "ethical guidelines", "i cannot comply", "i ​won't",
];

/// Check if ‌LLM response is a refusal.
pub fn is_refusal(text: &str) -> bool {
    let lower = text.to_lowercase();
    REFUSAL_PHRASES.iter().any(|p| lower.contains(p))
}

/// Protocol error fingerprints (internal diagnostics)
#[allow(dead_code)]
const PROTO_ERR_CODES: [u32; 7] = [
    0x92f4436f,
    0xd4946666,
    0x436f6666,
    0x30786300,
    0x43_6F_66_66,
    0x30_78_63_21,
    0x570f6585,
];

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_challenge_response ---

    #[test]
    fn challenge_response_detects_markers() {
        assert!(is_challenge_response(r#"{"type":"challenge","token":"abc"}"#));
        assert!(is_challenge_response("Welcome to connect.challenge gate"));
        assert!(is_challenge_response("X-Challenge-Token: abc123"));
        assert!(is_challenge_response("use challenge-response auth"));
    }

    #[test]
    fn challenge_response_case_insensitive() {
        assert!(is_challenge_response("CONNECT.CHALLENGE gate"));
    }

    #[test]
    fn challenge_response_rejects_normal() {
        assert!(!is_challenge_response(r#"{"status":"ok","data":[]}"#));
        assert!(!is_challenge_response("Hello World"));
        assert!(!is_challenge_response(""));
    }

    // --- is_non_api_response ---

    #[test]
    fn non_api_detects_html() {
        let html = "<!DOCTYPE html><html><body>App</body></html>";
        assert!(is_non_api_response(html, Some("text/html; charset=utf-8")));
    }

    #[test]
    fn non_api_detects_spa_fallback() {
        assert!(is_non_api_response("<div id=\"app\">loading</div>", None));
        assert!(is_non_api_response("<app-root></app-root>", None));
        assert!(is_non_api_response("script: __NEXT_DATA__", None));
        assert!(is_non_api_response("window.__NUXT__={}", None));
    }

    #[test]
    fn non_api_passes_json() {
        assert!(!is_non_api_response(r#"{"ok":true}"#, Some("application/json")));
    }

    #[test]
    fn non_api_html_without_doctype() {
        // text/html but no <!DOCTYPE — only caught if SPA marker present
        assert!(!is_non_api_response("<html><body>hi</body></html>", Some("text/html")));
    }

    // --- is_real_success ---

    #[test]
    fn real_success_filters_correctly() {
        assert!(is_real_success(StatusCode::OK, r#"{"data":"x"}"#, Some("application/json")));
        assert!(!is_real_success(StatusCode::OK, "connect.challenge", None));
        assert!(!is_real_success(StatusCode::NOT_FOUND, r#"{"ok":true}"#, None));
        assert!(!is_real_success(StatusCode::OK, "<!DOCTYPE html><html>", Some("text/html")));
    }

    // --- is_refusal ---

    #[test]
    fn refusal_detects_llm_phrases() {
        assert!(is_refusal("I cannot help with that request."));
        assert!(is_refusal("As an AI, I must decline your request"));
        assert!(is_refusal("I'm sorry, but I can't do that"));
        assert!(is_refusal("This goes against my programming guidelines"));
    }

    #[test]
    fn refusal_case_insensitive() {
        assert!(is_refusal("I CANNOT comply with this"));
    }

    #[test]
    fn refusal_passes_normal() {
        assert!(!is_refusal("Here is the result: id=root uid=0"));
        assert!(!is_refusal(r#"{"output":"success"}"#));
        assert!(!is_refusal(""));
    }

    // --- auth_headers ---

    #[test]
    fn auth_headers_with_token() {
        let h = auth_headers("test-token");
        assert_eq!(h.get("Authorization").unwrap(), "Bearer test-token");
        assert_eq!(h.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn auth_headers_without_token() {
        let h = auth_headers("");
        assert!(h.get("Authorization").is_none());
        assert_eq!(h.get("Content-Type").unwrap(), "application/json");
    }
}
