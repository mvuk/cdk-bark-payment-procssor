use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};

/// Backend-specific configuration for Ark (Bark) wallet
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackendConfig {
    /// BIP39 mnemonic for wallet seed
    pub mnemonic: String,

    /// Ark server address
    #[serde(default = "default_server_address")]
    pub server_address: String,

    /// Ark server access token. Mainnet `ark.second.tech` is access-token-gated; when set this is
    /// passed to bark's `Config::server_access_token` so the gRPC client sends it. Empty/unset on
    /// the local Mutinynet/regtest setup (no token required). Set via `ARK_SERVER_ACCESS_TOKEN`.
    #[serde(default)]
    pub server_access_token: String,

    /// Esplora API address
    #[serde(default = "default_esplora_address")]
    pub esplora_address: String,

    /// Bitcoin network (signet, testnet, mainnet)
    #[serde(default = "default_network")]
    pub network: String,

    /// Data directory for SQLite database
    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    /// Bitcoind RPC URL — used as the bark wallet's chain source (regtest)
    #[serde(default = "default_bitcoind_address")]
    pub bitcoind_address: String,

    /// Bitcoind RPC user
    #[serde(default = "default_bitcoind_user")]
    pub bitcoind_user: String,

    /// Bitcoind RPC password
    #[serde(default = "default_bitcoind_pass")]
    pub bitcoind_pass: String,

    /// Payjoin directory URL (v2 store-and-forward server).
    #[serde(default = "default_payjoin_directory_url")]
    pub payjoin_directory_url: String,

    /// OHTTP relay URL used to encapsulate payjoin requests to the directory.
    #[serde(default = "default_payjoin_ohttp_relay")]
    pub payjoin_ohttp_relay: String,

    /// OHTTP keys (bech32 `OH1...` string). If empty, they are fetched from the directory
    /// via the relay at startup.
    #[serde(default)]
    pub payjoin_ohttp_keys: String,

    /// Telemetry control URL for the on-ramp dashboard (POST `${control_url}/onramp/event`).
    #[serde(default = "default_control_url")]
    pub control_url: String,

    /// "Tier 2" payjoin boarding: when true, the mint (receiver) contributes its OWN on-chain
    /// input(s) to the payjoin board, turning the 1-input board into a real multi-input payjoin.
    /// Default false (Tier 3, zero receiver inputs — existing behavior). Toggled via the
    /// `PAYJOIN_RECEIVER_INPUTS` env var ("1"/"true").
    #[serde(default)]
    pub payjoin_receiver_inputs: bool,

    /// Number of mint UTXOs to contribute to a payjoin board when `payjoin_receiver_inputs` is on.
    /// The sender's single input becomes one-of-many so a chain observer cannot pick out the
    /// depositor's input. Clamped to the number of available UNLOCKED mint UTXOs; if zero are
    /// available the board falls back to the zero-input (Tier 3) path. Default 2. Set via the
    /// `PAYJOIN_RECEIVER_INPUT_COUNT` env var.
    #[serde(default = "default_payjoin_receiver_input_count")]
    pub payjoin_receiver_input_count: u32,

    /// The mint's own on-chain deposit (board) fee, in basis points of the user's deposit D.
    /// Deducted from the credited ecash; the fee stays inside the board VTXO as mint reserve, so
    /// total solvency is preserved by construction. Default 0 (no fee). Set via the
    /// `MINT_ONCHAIN_DEPOSIT_FEE_BPS` env var (e.g. 50 = 0.50%).
    #[serde(default)]
    pub payjoin_onchain_deposit_fee_bps: u64,
}

fn default_payjoin_receiver_input_count() -> u32 {
    2
}

fn default_payjoin_directory_url() -> String {
    "https://payjo.in".to_string()
}

fn default_payjoin_ohttp_relay() -> String {
    "https://pj.bobspacebkk.com".to_string()
}

fn default_control_url() -> String {
    "http://127.0.0.1:9201".to_string()
}

fn default_server_address() -> String {
    "https://ark.signet.2nd.dev".to_string()
}

fn default_esplora_address() -> String {
    "https://esplora.signet.2nd.dev".to_string()
}

fn default_network() -> String {
    "signet".to_string()
}

fn default_data_dir() -> String {
    ".data/bark".to_string()
}

fn default_bitcoind_address() -> String {
    "http://127.0.0.1:18443".to_string()
}

fn default_bitcoind_user() -> String {
    "ark".to_string()
}

fn default_bitcoind_pass() -> String {
    "ark".to_string()
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            mnemonic: String::new(),
            server_address: default_server_address(),
            server_access_token: String::new(),
            esplora_address: default_esplora_address(),
            network: default_network(),
            data_dir: default_data_dir(),
            bitcoind_address: default_bitcoind_address(),
            bitcoind_user: default_bitcoind_user(),
            bitcoind_pass: default_bitcoind_pass(),
            payjoin_directory_url: default_payjoin_directory_url(),
            payjoin_ohttp_relay: default_payjoin_ohttp_relay(),
            payjoin_ohttp_keys: String::new(),
            control_url: default_control_url(),
            payjoin_receiver_inputs: false,
            payjoin_receiver_input_count: default_payjoin_receiver_input_count(),
            payjoin_onchain_deposit_fee_bps: 0,
        }
    }
}

/// Main configuration structure
///
/// Loads configuration from config.toml and environment variables.
/// Environment variables take precedence over file configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    /// Backend type identifier (e.g., "ark")
    #[serde(default)]
    pub backend_type: String,

    /// Backend-specific configuration
    #[serde(default)]
    pub backend: BackendConfig,

    /// gRPC server port
    pub server_port: u16,

    /// TLS config for gRPC server
    pub tls_enable: bool,
    pub tls_cert_path: String,
    pub tls_key_path: String,

    /// HTTP/2 keep-alive interval (e.g., "30s")
    #[serde(default)]
    pub keep_alive_interval: Option<String>,

    /// HTTP/2 keep-alive timeout (e.g., "10s")
    #[serde(default)]
    pub keep_alive_timeout: Option<String>,

    /// Maximum connection age (e.g., "30m")
    #[serde(default)]
    pub max_connection_age: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            backend_type: "ark".to_string(),
            backend: BackendConfig::default(),
            server_port: 50051,
            tls_enable: false,
            tls_cert_path: "certs/server.crt".to_string(),
            tls_key_path: "certs/server.key".to_string(),
            keep_alive_interval: None,
            keep_alive_timeout: None,
            max_connection_age: None,
        }
    }
}

impl Config {
    /// Load from config.toml (if present) and environment variables.
    /// Environment variables override file values.
    pub fn load() -> Self {
        // 1) Start with defaults + config.toml only if it exists
        let base: Config = Default::default();
        let mut fig = Figment::from(Serialized::defaults(base));
        if std::path::Path::new("config.toml").exists() {
            fig = fig.merge(Toml::file("config.toml"));
        }
        let mut cfg: Config = fig.extract().unwrap_or_default();

        // 2) Overlay environment variables explicitly
        // Seed precedence: MNEMONIC_FILE (a path; read + trim) wins over the inline MNEMONIC value
        // so the seed can be injected via a file (Key Vault / tmpfs) rather than a process-visible
        // env value. Falls back to MNEMONIC when MNEMONIC_FILE is unset.
        if let Ok(path) = std::env::var("MNEMONIC_FILE") {
            match std::fs::read_to_string(&path) {
                Ok(contents) => cfg.backend.mnemonic = contents.trim().to_string(),
                Err(e) => panic!("Failed to read MNEMONIC_FILE '{}': {}", path, e),
            }
        } else if let Ok(v) = std::env::var("MNEMONIC") {
            cfg.backend.mnemonic = v;
        }
        if let Ok(v) = std::env::var("ARK_SERVER_ADDRESS") {
            cfg.backend.server_address = v;
        }
        if let Ok(v) = std::env::var("ARK_SERVER_ACCESS_TOKEN") {
            cfg.backend.server_access_token = v;
        }
        if let Ok(v) = std::env::var("ESPLORA_ADDRESS") {
            cfg.backend.esplora_address = v;
        }
        if let Ok(v) = std::env::var("NETWORK") {
            cfg.backend.network = v;
        }
        if let Ok(v) = std::env::var("DATA_DIR") {
            cfg.backend.data_dir = v;
        }
        if let Ok(v) = std::env::var("SERVER_PORT") {
            cfg.server_port = v.parse().unwrap_or(cfg.server_port);
        }
        if let Ok(v) = std::env::var("TLS_ENABLE") {
            cfg.tls_enable = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES");
        }
        if let Ok(v) = std::env::var("TLS_CERT_PATH") {
            cfg.tls_cert_path = v;
        }
        if let Ok(v) = std::env::var("TLS_KEY_PATH") {
            cfg.tls_key_path = v;
        }
        if let Ok(v) = std::env::var("PAYJOIN_DIRECTORY_URL") {
            cfg.backend.payjoin_directory_url = v;
        }
        if let Ok(v) = std::env::var("PAYJOIN_OHTTP_RELAY") {
            cfg.backend.payjoin_ohttp_relay = v;
        }
        if let Ok(v) = std::env::var("PAYJOIN_OHTTP_KEYS") {
            cfg.backend.payjoin_ohttp_keys = v;
        }
        if let Ok(v) = std::env::var("CONTROL_URL") {
            cfg.backend.control_url = v;
        }
        if let Ok(v) = std::env::var("PAYJOIN_RECEIVER_INPUTS") {
            cfg.backend.payjoin_receiver_inputs =
                matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES");
        }
        if let Ok(v) = std::env::var("PAYJOIN_RECEIVER_INPUT_COUNT") {
            if let Ok(n) = v.parse::<u32>() {
                cfg.backend.payjoin_receiver_input_count = n;
            }
        }
        if let Ok(v) = std::env::var("MINT_ONCHAIN_DEPOSIT_FEE_BPS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.backend.payjoin_onchain_deposit_fee_bps = n;
            }
        }

        cfg
    }

    pub fn from_env() -> Self {
        Self::load()
    }
}
