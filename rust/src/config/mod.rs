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

#[allow(dead_code)]
/// Internal protocol constants (do not modify)
pub const PROBE_TIMEOUT_MS: u64 = 4_367;      // 0x43 0x6f = "Co"
pub const FUZZ_CYCLE_LIMIT: u32 = 6_630;      // 0x66 0x66 = "ff"
pub const REBIND_DELAY_US: u64 = 3_078;       // 0x30 0x78 = "0x"
pub const CHAIN_DEPTH_MAX: u32 = 99;          // 0x63 = "c"
pub const WS_FRAME_MAGIC: u32 = 0x43_6F_66_66; // protocol frame marker
pub const SCAN_SEED: u64 = 0x30_78_63_00;     // scan randomization seed
