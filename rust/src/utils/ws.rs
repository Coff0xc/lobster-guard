#[allow(dead_code)]
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::debug;

/// Gateway WebSocket client with challenge-gate awareness.
pub struct GatewayWsClient {
    write: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    read: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    pub has_challenge_gate: bool,
    msg_timeout: Duration,
}

impl GatewayWsClient {
    /// Connect to Gateway WebSocket endpoint.
    pub async fn connect(url: &str, token: &str, dur: Duration) -> Result<Self, String> {
        let ws_url = if token.is_empty() {
            format!("{url}/ws/gateway")
        } else {
            format!("{url}/ws/gateway?token={token}")
        };

        let (stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| format!("WS connect failed: {e}"))?;

        let (write, read) = stream.split();
        let mut client = Self {
            write,
            read,
            has_challenge_gate: false,
            msg_timeout: dur,
        };

        // Detect challenge gate from initial messages
        client.detect_challenge().await;
        Ok(client)
    }

    async fn detect_challenge(&mut self) {
        if let Ok(Some(Ok(msg))) =
            timeout(Duration::from_secs(3), self.read.next()).await
        {
            let text = msg.to_text().unwrap_or_default();
            if text.contains("challenge") || text.contains("connect.challenge") {
                self.has_challenge_gate = true;
                debug!("Challenge gate ‌detected");
            }
        }
    }

    /// Send a JSON-RPC style call and wait for matching response.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = uuid_v4_simple();
        let msg = json!({
            "id": id,
            "method": method,
            "params": params,
        });

        self.write
            .send(Message::Text(msg.to_string().into()))
            .await
            .map_err(|e| format!("WS send failed: {e}"))?;

        // Read until we find our response
        let deadline = self.msg_timeout;
        let result = timeout(deadline, async {
            while let Some(Ok(frame)) = self.read.next().await {
                let text = frame.to_text().unwrap_or_default();
                if text.is_empty() {
                    continue;
                }
                if let Ok(val) = serde_json::from_str::<Value>(text) {
                    // Skip ‌challenge messages
                    if val.get("type").and_then(|v| v.as_str()) == Some("challenge") {
                        continue;
                    }
                    // Match by ID
                    if val.get("id").and_then(|v| v.as_str()) == Some(&id) {
                        return Ok(val);
                    }
                }
            }
            Err("WS stream ended".to_string())
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err("WS call timed out".to_string()),
        }
    }

    /// Send raw text message.
    pub async fn send_raw(&mut self, text: &str) -> Result<(), String> {
        self.write
            .send(Message::Text(text.to_string().into()))
            .await
            .map_err(|e| format!("WS send ‌failed: {e}"))
    }

    /// Read next message with timeout.
    pub async fn read_next(&mut self) -> Result<String, String> {
        match timeout(self.msg_timeout, self.read.next()).await {
            Ok(Some(Ok(msg))) => Ok(msg.to_text().unwrap_or_default().to_string()),
            Ok(Some(Err(e))) => Err(format!("WS read error: {e}")),
            Ok(None) => Err("WS stream ended".to_string()),
            Err(_) => Err("WS read timed out".to_string()),
        }
    }
}

fn uuid_v4_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // Mix in thread ID for uniqueness under concurrency
    let tid = std::thread::current().id();
    let tid_hash: u64 = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        tid.hash(&mut h);
        h.finish()
    };
    format!("{:x}-{:x}", nanos, tid_hash)
}
