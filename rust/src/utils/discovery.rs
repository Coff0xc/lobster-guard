//! Port scanning and OpenClaw service discovery

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use std::sync::Arc;

/// Default ports commonly used by OpenClaw/Open-WebUI
pub const COMMON_PORTS: &[u16] = &[
    80, 443, 3000, 3001, 5000, 8000, 8080, 8443, 8888, 9090,
];

/// Result of a port scan
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub host: String,
    pub open_ports: Vec<u16>,
}

/// Result of service fingerprinting
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub host: String,
    pub port: u16,
    pub is_openclaw: bool,
    pub version: Option<String>,
    pub features: Vec<String>,
}

/// Scan specified ports on a host using TCP connect scan
pub async fn scan_ports(host: &str, ports: &[u16], timeout_ms: u64, concurrency: usize) -> PortScanResult {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let sem = sem.clone();
        let host = host.to_string();
        let dur = Duration::from_millis(timeout_ms);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr: SocketAddr = match format!("{host}:{port}").parse() {
                Ok(a) => a,
                Err(_) => {
                    // Try DNS resolution for hostnames
                    match tokio::net::lookup_host(format!("{host}:{port}")).await {
                        Ok(mut addrs) => match addrs.next() {
                            Some(a) => a,
                            None => return None,
                        },
                        Err(_) => return None,
                    }
                }
            };
            match timeout(dur, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        }));
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(port)) = h.await {
            open_ports.push(port);
        }
    }
    open_ports.sort();

    PortScanResult {
        host: host.to_string(),
        open_ports,
    }
}

/// Check if an HTTP service on host:port is an OpenClaw instance
pub async fn fingerprint_openclaw(host: &str, port: u16, tls: bool, dur: Duration) -> ServiceInfo {
    let scheme = if tls { "https" } else { "http" };
    let base = format!("{scheme}://{host}:{port}");
    let client = crate::utils::build_client(dur);

    let mut is_openclaw = false;
    let mut version: Option<String> = None;
    let mut features = Vec::new();

    // Probe /api/config — most distinctive OpenClaw endpoint
    if let Ok(resp) = client.get(format!("{base}/api/config")).send().await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                if text.contains("\"name\"") || text.contains("open-webui") || text.contains("openclaw") {
                    is_openclaw = true;
                    features.push("config_api".into());
                    // Try extracting version
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(v) = val.get("version").and_then(|v| v.as_str()) {
                            version = Some(v.to_string());
                        }
                    }
                }
            }
        }
    }

    // Probe /api/v1/auths/
    if let Ok(resp) = client.get(format!("{base}/api/v1/auths/")).send().await {
        if resp.status().is_success() || resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
            features.push("auth_api".into());
            if !is_openclaw {
                is_openclaw = true;
            }
        }
    }

    // Probe /health
    if let Ok(resp) = client.get(format!("{base}/health")).send().await {
        if resp.status().is_success() {
            features.push("health".into());
        }
    }

    // Check root for OpenClaw markers
    if let Ok(resp) = client.get(&base).send().await {
        // Check server header
        if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
            let sl = server.to_lowercase();
            if sl.contains("open-webui") || sl.contains("openclaw") {
                is_openclaw = true;
            }
        }
        if let Ok(body) = resp.text().await {
            if body.contains("open-webui") || body.contains("Open WebUI") || body.contains("openclaw") {
                is_openclaw = true;
                features.push("web_ui".into());
            }
        }
    }

    // Check WebSocket availability
    if let Ok(resp) = client.get(format!("{base}/ws")).send().await {
        if resp.status().as_u16() == 101 || resp.status().as_u16() == 426 {
            features.push("websocket".into());
        }
    }

    ServiceInfo {
        host: host.to_string(),
        port,
        is_openclaw,
        version,
        features,
    }
}

/// Discover OpenClaw services on a host across specified ports
pub async fn discover_services(host: &str, ports: &[u16], tls: bool, dur: Duration, concurrency: usize) -> Vec<ServiceInfo> {
    let scan = scan_ports(host, ports, dur.as_millis() as u64, concurrency).await;

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for port in scan.open_ports {
        let sem = sem.clone();
        let host = host.to_string();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            fingerprint_openclaw(&host, port, tls, dur).await
        }));
    }

    let mut services = Vec::new();
    for h in handles {
        if let Ok(info) = h.await {
            if info.is_openclaw {
                services.push(info);
            }
        }
    }
    services
}

/// Parse port specification (e.g., "8080", "80,443,8080", "8000-9000")
pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                if start <= end {
                    ports.extend(start..=end);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_single() {
        assert_eq!(parse_ports("8080"), vec![8080]);
    }

    #[test]
    fn parse_ports_comma_separated() {
        assert_eq!(parse_ports("80,443,8080"), vec![80, 443, 8080]);
    }

    #[test]
    fn parse_ports_range() {
        assert_eq!(parse_ports("8000-8003"), vec![8000, 8001, 8002, 8003]);
    }

    #[test]
    fn parse_ports_mixed() {
        assert_eq!(parse_ports("80,8000-8002,9090"), vec![80, 8000, 8001, 8002, 9090]);
    }

    #[test]
    fn parse_ports_empty() {
        assert_eq!(parse_ports(""), Vec::<u16>::new());
    }

    #[test]
    fn parse_ports_invalid() {
        assert_eq!(parse_ports("abc,xyz"), Vec::<u16>::new());
    }

    #[test]
    fn parse_ports_mixed_invalid() {
        assert_eq!(parse_ports("80,bad,443"), vec![80, 443]);
    }

    #[test]
    fn parse_ports_whitespace() {
        assert_eq!(parse_ports(" 80 , 443 "), vec![80, 443]);
    }

    #[test]
    fn parse_ports_reversed_range() {
        assert_eq!(parse_ports("9000-8000"), Vec::<u16>::new());
    }

    #[test]
    fn port_scan_result_construction() {
        let r = PortScanResult {
            host: "127.0.0.1".into(),
            open_ports: vec![80, 443],
        };
        assert_eq!(r.host, "127.0.0.1");
        assert_eq!(r.open_ports.len(), 2);
    }

    #[test]
    fn service_info_construction() {
        let s = ServiceInfo {
            host: "example.com".into(),
            port: 8080,
            is_openclaw: true,
            version: Some("0.5.0".into()),
            features: vec!["auth_api".into(), "websocket".into()],
        };
        assert!(s.is_openclaw);
        assert_eq!(s.version.as_deref(), Some("0.5.0"));
        assert_eq!(s.features.len(), 2);
    }
}
