#[allow(dead_code)]
use std::time::Duration;

/// Unified configuration for all exploit modules and chain execution.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    pub token: String,
    pub timeout: Duration,
    pub callback_url: Option<String>,
    pub hook_token: Option<String>,
    pub hook_path: Option<String>,
    pub concurrency: usize,
    pub aggressive: bool,
    pub quiet: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            token: String::new(),
            timeout: Duration::from_secs(10),
            callback_url: None,
            hook_token: None,
            hook_path: None,
            concurrency: 10,
            aggressive: false,
            quiet: false,
        }
    }
}
