use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, anyhow, ensure};
use k256::ecdsa::SigningKey;
use morph_core::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::conditional_packages::StoredConditionalBatchPackage;
use crate::multi_asset_funding::{
    RootCollectionSummary, RootFundingCollection, RootFundingDraft, RootFundingTarget,
};
use crate::multi_asset_packages::{MultiAssetPackageSummary, StoredMultiAssetPackage};
use crate::multi_asset_signatures::SignatureMessage;
use crate::rpc::CkbRpcClient;
use crate::watch_alert::{WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert};

const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_EVENTS: usize = 128;
const MAX_WATCHTOWER_ALERTS: usize = 32;
const WATCHTOWER_ALERT_SCHEMA: &str = "morph.watchtower_alert";
const EVENT_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(1_000);
const EVENT_STREAM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const RPC_HEALTH_CACHE_TTL: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_MUTATIONS: usize = 4;
const MAX_CONCURRENT_SSE_STREAMS: usize = 8;
const MUTATION_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_MUTATIONS_PER_WINDOW: u32 = 120;
const MAX_INVOICE_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_ROOT_FUNDINGS: usize = 32;
const MAX_MULTI_ASSET_RECOVERY_PACKAGES: usize = 4096;
const MAX_MULTI_ASSET_PACKAGE_VIEWS: usize = 32;

pub struct HubServeOptions {
    pub listen: String,
    pub state_path: PathBuf,
    pub pubkey: String,
    pub network: MorphNetwork,
    pub invoice_private_key: Option<String>,
    pub ckb_rpc_url: Option<String>,
    pub watch_alert_file: Option<PathBuf>,
    pub ui_dir: PathBuf,
    pub auth_token: Option<String>,
    pub allow_unauthenticated_loopback: bool,
    pub allow_state_restore: bool,
    pub cors_origin: Option<String>,
}

struct HubServer {
    store: Arc<Mutex<HubStore>>,
    rpc_cache: Arc<Mutex<RpcHealthCache>>,
    watch_alert_cache: Arc<Mutex<WatchtowerAlertCache>>,
    active_connections: Arc<AtomicUsize>,
    active_mutations: Arc<AtomicUsize>,
    active_sse_streams: Arc<AtomicUsize>,
    request_counter: Arc<AtomicU64>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    ui_dir: PathBuf,
    ckb_rpc_url: Option<String>,
    watch_alert_file: Option<PathBuf>,
    invoice_signing_key: Option<SigningKey>,
    auth_token: Option<HubAuthToken>,
    allow_unauthenticated_loopback: bool,
    allow_state_restore: bool,
    cors_origin: Option<String>,
}

#[derive(Clone)]
struct HubStore {
    path: PathBuf,
    state: HubRuntimeState,
    next_event_id: u64,
}

#[derive(Clone)]
struct HubRuntimeState {
    pubkey: String,
    peer_pubkeys: BTreeMap<Bytes32, String>,
    node: MorphNodeState,
    conditional_batches: BTreeMap<Bytes32, StoredConditionalBatchPackage>,
    multi_asset_packages: BTreeMap<(Bytes32, Bytes32, u64), HubMultiAssetPackage>,
    root_fundings: BTreeMap<Bytes32, HubRootFunding>,
    events: Vec<HubEvent>,
}

#[derive(Clone)]
struct HubMultiAssetPackage {
    package: StoredMultiAssetPackage,
    summary: MultiAssetPackageSummary,
}

#[derive(Clone)]
struct HubRootFunding {
    collection: RootFundingCollection,
    summary: RootCollectionSummary,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootReceiptRequest {
    target: RootFundingTarget,
    receipt: SignatureMessage,
}

#[derive(Default)]
struct RpcHealthCache {
    value: Option<CachedRpcView>,
    refresh_in_flight: bool,
}

#[derive(Default)]
struct WatchtowerAlertCache {
    path: Option<PathBuf>,
    modified: Option<SystemTime>,
    len: u64,
    value: Option<(bool, Vec<WatchtowerAlertView>, Option<String>)>,
}

struct RateLimiter {
    window_started: Instant,
    mutating_requests: u32,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            window_started: Instant::now(),
            mutating_requests: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct HubAuthToken {
    secret_hash: Bytes32,
    scopes: BTreeSet<AuthScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthScope {
    Read,
    Write,
    Restore,
    Sign,
}

struct CounterPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for CounterPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

struct CachedRpcView {
    url: String,
    checked_at: Instant,
    view: RpcView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedHubState {
    pubkey: String,
    network: MorphNetwork,
    peers: Vec<PersistedPeer>,
    channels: Vec<PersistedChannel>,
    factories: Vec<PersistedFactory>,
    conditional_batches: Vec<StoredConditionalBatchPackage>,
    multi_asset_packages: Vec<StoredMultiAssetPackage>,
    root_fundings: Vec<RootFundingCollection>,
    invoices: Vec<StoredMorphInvoice>,
    completed_flows: Vec<MorphBusinessFlow>,
    events: Vec<HubEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPeer {
    pubkey: String,
    alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedChannel {
    channel_id: String,
    counterparty_pubkey: String,
    funding_epoch: u64,
    funding_context_id: String,
    state_number: u64,
    phase: Phase,
    balances: Vec<MorphAssetBalance>,
    sponsor_budget: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedFactory {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    update_number: u64,
    reserve_balances: Vec<MorphAssetBalance>,
    materialised_child_channels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubEvent {
    id: u64,
    severity: EventSeverity,
    event: String,
    subject_id: Option<Bytes32>,
    message: String,
    created_at_unix: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
    code: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct RestorePreview {
    confirmation_hash: String,
    allowed: bool,
    current: RestoreStateSummary,
    candidate: RestoreStateSummary,
    ignored_completed_flows: Vec<&'static str>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RestoreStateSummary {
    peers: usize,
    channels: usize,
    factories: usize,
    conditional_batches: usize,
    multi_asset_packages: usize,
    root_fundings: usize,
    invoices: usize,
    completed_flows: usize,
    events: usize,
    settling_channels: usize,
}

impl RestoreStateSummary {
    fn from_runtime(state: &HubRuntimeState) -> Self {
        Self {
            peers: state.node.peers.len(),
            channels: state.node.channels.len(),
            factories: state.node.factories.len(),
            conditional_batches: state.conditional_batches.len(),
            multi_asset_packages: state.multi_asset_packages.len(),
            root_fundings: state.root_fundings.len(),
            invoices: state.node.invoices.records().count(),
            completed_flows: state.node.completed_flows.len(),
            events: state.events.len(),
            settling_channels: state
                .node
                .channels
                .values()
                .filter(|channel| channel.phase == Phase::Settling)
                .count(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RestoreStateFileRequest {
    state: PersistedHubState,
    confirmation_hash: String,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct CreateInvoiceRequest {
    amount: String,
    description: String,
    payment_preimage: Option<String>,
    payment_hash: Option<String>,
    expiry_secs: u64,
    channel_id: Option<String>,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct DecodeInvoiceRequest {
    encoded_invoice: String,
}

#[derive(Debug, Deserialize)]
struct SettleInvoiceRequest {
    payment_preimage: String,
}

#[derive(Debug, Deserialize)]
struct ConnectPeerRequest {
    pubkey: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
struct OpenChannelRequest {
    channel_id: String,
    counterparty_pubkey: String,
    counterparty_alias: Option<String>,
    funding_context_id: String,
    local: String,
    remote: String,
    pending: Option<String>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct SpliceChannelRequest {
    new_funding_epoch: u64,
    new_funding_context_id: String,
}

#[derive(Debug, Deserialize)]
struct PublishStateRequest {
    funding_context_id: String,
    state_number: u64,
}

#[derive(Debug, Deserialize)]
struct OpenFactoryRequest {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    reserve: String,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Deserialize)]
struct AdvanceFactoryRequest {
    new_update_number: u64,
}

#[derive(Debug, Deserialize)]
struct MaterialiseChildRequest {
    child_channel_id: String,
    counterparty_pubkey: String,
    counterparty_alias: Option<String>,
    funding_context_id: String,
    local: String,
    remote: String,
    pending: Option<String>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AssetRequest {
    Ckb,
    Xudt { type_hash: String },
}

#[derive(Serialize)]
struct HubView {
    pubkey: String,
    node_id: String,
    network: &'static str,
    state_path: String,
    rpc: RpcView,
    security: HubSecurityView,
    model: HubModelView,
    provenance: RecordProvenanceView,
    watchtower: WatchtowerView,
    peers: Vec<PeerView>,
    channels: Vec<ChannelView>,
    invoices: Vec<InvoiceView>,
    factories: Vec<FactoryView>,
    conditional_batches: Vec<StoredConditionalBatchPackage>,
    multi_asset_packages: Vec<MultiAssetPackageSummary>,
    multi_asset_package_count: usize,
    root_fundings: Vec<RootCollectionSummary>,
    events: Vec<EventView>,
    required_flows: Vec<&'static str>,
    completed_flows: Vec<&'static str>,
    missing_flows: Vec<&'static str>,
}

#[derive(Serialize)]
struct HubModelView {
    profile: &'static str,
    hub_role: &'static str,
    factory_authority: &'static str,
    channel_authority: &'static str,
    routing_role: &'static str,
    agent_role: &'static str,
    factory_min_participants: usize,
    factory_max_participants: usize,
    chain_actions_enabled: bool,
    factory_rights_exposed: bool,
    provider_edges_exposed: bool,
    rgbpp_evidence_exposed: bool,
    agent_receipts_exposed: bool,
}

#[derive(Serialize)]
struct HubSecurityView {
    auth_required: bool,
    auth_mode: &'static str,
    auth_scopes: Vec<AuthScope>,
    single_operator: bool,
    state_restore_enabled: bool,
    invoice_signing_enabled: bool,
    cors_origin: Option<String>,
    max_concurrent_connections: usize,
    max_concurrent_mutations: usize,
    max_concurrent_event_streams: usize,
    mutation_rate_limit_per_minute: u32,
    max_invoice_expiry_secs: u64,
}

#[derive(Serialize, Clone, Copy)]
struct RecordProvenanceView {
    source: &'static str,
    chain_status: &'static str,
    label: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct WatchtowerView {
    configured: bool,
    alert_file: Option<String>,
    file_exists: bool,
    alerts: Vec<WatchtowerAlertView>,
    last_error: Option<String>,
    provenance: RecordProvenanceView,
}

#[derive(Serialize, Clone)]
struct WatchtowerAlertView {
    schema: String,
    created_unix_ms: u64,
    channel_id: String,
    severity: WatchAlertSeverity,
    event: WatchAlertEvent,
    message: String,
    selected_state_number: u64,
    observed_state_number: Option<u64>,
    observed_out_point: Option<String>,
    publication_tx_hash: Option<String>,
    selected_funding_anchor: Option<String>,
    observed_funding_anchor: Option<String>,
    selected_funding_context_id: Option<String>,
    observed_funding_context_id: Option<String>,
    scanned_to_block: u64,
    next_from_block: u64,
    provenance: RecordProvenanceView,
}

#[derive(Clone, Serialize)]
struct RpcView {
    status: &'static str,
    url: Option<String>,
    tip_height: Option<u64>,
    chain: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
struct PeerView {
    pubkey: String,
    node_id: String,
    alias: String,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct ChannelView {
    channel_id: String,
    factory_id: Option<String>,
    counterparty_pubkey: String,
    counterparty_node_id: String,
    funding_epoch: u64,
    funding_context_id: String,
    state_number: u64,
    phase: &'static str,
    balances: Vec<BalanceView>,
    sponsor_budget: u64,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct BalanceView {
    asset: AssetView,
    local: String,
    remote: String,
    pending: String,
}

#[derive(Serialize)]
struct InvoiceView {
    invoice_id: String,
    encoded_invoice: String,
    status: &'static str,
    network: &'static str,
    payee_pubkey: Option<String>,
    payee_node_id: String,
    channel_id: Option<String>,
    asset: AssetView,
    amount: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    payment_hash: String,
    description: String,
    received_at_unix: Option<u64>,
    paid_at_unix: Option<u64>,
    cancelled_at_unix: Option<u64>,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct FactoryView {
    factory_id: String,
    participant_pubkeys: Vec<String>,
    participant_node_ids: Vec<String>,
    update_number: u64,
    reserve_balances: Vec<BalanceView>,
    materialised_child_channels: Vec<String>,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
struct EventView {
    id: u64,
    severity: EventSeverity,
    event: String,
    subject_id: Option<String>,
    message: String,
    created_at_unix: u64,
    provenance: RecordProvenanceView,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AssetView {
    Ckb,
    Xudt { type_hash: String },
}

fn local_state_provenance() -> RecordProvenanceView {
    RecordProvenanceView {
        source: "hub_state_file",
        chain_status: "not_chain_verified",
        label: "Local only",
        message: "Recorded in the Morph Hub state file only; this is not CKB devnet confirmation.",
    }
}

fn hub_model_view() -> HubModelView {
    HubModelView {
        profile: "morph-v3-conditional-batch",
        hub_role: "local_operator_projection",
        factory_authority: "factory_state_and_vault",
        channel_authority: "state_and_vault",
        routing_role: "external_optional_provider",
        agent_role: "application_sidecar",
        factory_min_participants: FACTORY_MIN_PARTICIPANTS,
        factory_max_participants: FACTORY_MAX_PARTICIPANTS,
        chain_actions_enabled: false,
        factory_rights_exposed: false,
        provider_edges_exposed: false,
        rgbpp_evidence_exposed: false,
        agent_receipts_exposed: false,
    }
}

fn watchtower_alert_provenance() -> RecordProvenanceView {
    RecordProvenanceView {
        source: "watchtower_alert_file",
        chain_status: "watchtower_alert",
        label: "Watchtower alert",
        message: "Parsed from the Morph watchtower alert JSONL file emitted by the watchtower service.",
    }
}

fn normalise_optional_secret(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_hub_auth_token(value: Option<String>) -> Result<Option<HubAuthToken>> {
    let Some(value) = normalise_optional_secret(value) else {
        return Ok(None);
    };
    if let Some((scope_prefix, secret)) = value.split_once(':') {
        let secret = secret.trim().to_string();
        let scopes = scope_prefix
            .split(',')
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(parse_auth_scope)
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            !secret.is_empty(),
            "Morph Hub auth token secret must not be empty"
        );
        ensure!(
            !scopes.is_empty(),
            "Morph Hub scoped token must include at least one scope"
        );
        Ok(Some(HubAuthToken {
            secret_hash: blake2b256(secret.as_bytes()),
            scopes,
        }))
    } else {
        Ok(Some(HubAuthToken {
            secret_hash: blake2b256(value.as_bytes()),
            scopes: all_auth_scopes(),
        }))
    }
}

fn parse_auth_scope(scope: &str) -> Result<AuthScope> {
    match scope {
        "read" => Ok(AuthScope::Read),
        "write" => Ok(AuthScope::Write),
        "restore" => Ok(AuthScope::Restore),
        "sign" => Ok(AuthScope::Sign),
        _ => Err(anyhow!(
            "unsupported Morph Hub auth scope {scope}; expected read, write, restore, or sign"
        )),
    }
}

fn all_auth_scopes() -> BTreeSet<AuthScope> {
    [
        AuthScope::Read,
        AuthScope::Write,
        AuthScope::Restore,
        AuthScope::Sign,
    ]
    .into_iter()
    .collect()
}

fn auth_scope_label(scope: AuthScope) -> &'static str {
    match scope {
        AuthScope::Read => "read",
        AuthScope::Write => "write",
        AuthScope::Restore => "restore",
        AuthScope::Sign => "sign",
    }
}

fn normalise_cors_origin(value: Option<String>) -> Result<Option<String>> {
    let Some(origin) = value.map(|raw| raw.trim().to_string()) else {
        return Ok(None);
    };
    if origin.is_empty() {
        return Ok(None);
    }
    ensure!(origin != "*", "--cors-origin must not be wildcard '*'");
    let parsed = url::Url::parse(&origin).context("--cors-origin must be a valid URL origin")?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "--cors-origin must be an http:// or https:// origin"
    );
    ensure!(
        parsed.host_str().is_some(),
        "--cors-origin must include a host"
    );
    ensure!(
        parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none(),
        "--cors-origin must be an origin only, without a path, query, or fragment"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "--cors-origin must not include user information"
    );
    Ok(Some(origin.trim_end_matches('/').to_string()))
}

fn listen_is_loopback(listen: &str) -> bool {
    listen_host(listen)
        .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "::1")
}

fn listen_host(listen: &str) -> Option<String> {
    let listen = listen.trim();
    if listen.is_empty() {
        return None;
    }
    if let Some(rest) = listen.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return Some(host.to_string());
    }
    let (host, _) = listen.rsplit_once(':')?;
    Some(host.to_string())
}

pub fn serve(options: HubServeOptions) -> Result<()> {
    let auth_token = parse_hub_auth_token(options.auth_token)?;
    let cors_origin = normalise_cors_origin(options.cors_origin)?;
    let invoice_signing_key = options
        .invoice_private_key
        .as_deref()
        .map(|value| parse_signing_key(value, "--invoice-private-key"))
        .transpose()?;
    if let Some(signing_key) = &invoice_signing_key {
        let signing_pubkey = hex::encode(signing_key_pubkey_sec1(signing_key));
        let configured_pubkey = canonical_pubkey(&options.pubkey)?;
        ensure!(
            signing_pubkey == configured_pubkey,
            "--invoice-private-key must derive the same compressed public key as --pubkey"
        );
    }
    ensure!(
        auth_token.is_some()
            || (listen_is_loopback(&options.listen) && options.allow_unauthenticated_loopback),
        "serving Morph Hub now requires --auth-token, --auth-token-file, --auth-token-stdin, --rotate-auth-token-on-restart, or MORPH_HUB_AUTH_TOKEN; for local development only, pass --allow-unauthenticated-loopback"
    );
    let listener = TcpListener::bind(&options.listen)
        .with_context(|| format!("failed to bind Morph hub to {}", options.listen))?;
    let store = HubStore::load_or_create(options.state_path, &options.pubkey, options.network)?;
    let server = Arc::new(HubServer {
        store: Arc::new(Mutex::new(store)),
        rpc_cache: Arc::new(Mutex::new(RpcHealthCache::default())),
        watch_alert_cache: Arc::new(Mutex::new(WatchtowerAlertCache::default())),
        active_connections: Arc::new(AtomicUsize::new(0)),
        active_mutations: Arc::new(AtomicUsize::new(0)),
        active_sse_streams: Arc::new(AtomicUsize::new(0)),
        request_counter: Arc::new(AtomicU64::new(1)),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        ui_dir: options.ui_dir,
        ckb_rpc_url: options.ckb_rpc_url,
        watch_alert_file: options.watch_alert_file,
        invoice_signing_key,
        auth_token,
        allow_unauthenticated_loopback: options.allow_unauthenticated_loopback,
        allow_state_restore: options.allow_state_restore,
        cors_origin,
    });

    println!("morph_hub_listen=http://{}", options.listen);
    println!("morph_hub_state={}", server.store_lock()?.path.display());
    println!("morph_hub_ui={}", server.ui_dir.display());
    if let Some(path) = &server.watch_alert_file {
        println!("morph_hub_watch_alert_file={}", path.display());
    }
    println!(
        "morph_hub_auth={}",
        if let Some(auth_token) = &server.auth_token {
            println!(
                "morph_hub_auth_scopes={}",
                auth_token
                    .scopes
                    .iter()
                    .copied()
                    .map(auth_scope_label)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            "required"
        } else {
            "explicit-unauthenticated-loopback"
        }
    );
    if server.auth_token.is_none() {
        eprintln!(
            "warning: Morph Hub is running without API authentication because --allow-unauthenticated-loopback was set; do not expose this listener outside the local machine"
        );
    } else if !listen_is_loopback(&options.listen) {
        eprintln!(
            "warning: Morph Hub is bound to {}; the bearer token is the API access gate, so keep it out of shell history and shared logs",
            options.listen
        );
    }
    println!(
        "morph_hub_state_restore={}",
        if server.allow_state_restore {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "morph_hub_invoice_signing={}",
        if server.invoice_signing_key.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    );
    if let Some(origin) = &server.cors_origin {
        println!("morph_hub_cors_origin={origin}");
    }
    server.refresh_rpc_cache();

    for stream in listener.incoming() {
        let mut stream = stream.context("failed to accept Morph hub connection")?;
        let Some(connection_permit) = try_acquire_counter(
            Arc::clone(&server.active_connections),
            MAX_CONCURRENT_CONNECTIONS,
        ) else {
            let _ = write_response(
                &mut stream,
                api_error_response(
                    503,
                    "Service Unavailable",
                    "too_many_connections",
                    "too many concurrent Morph Hub connections",
                    "accept",
                ),
                server.cors_origin.as_deref(),
            );
            continue;
        };
        let server = Arc::clone(&server);
        thread::spawn(move || {
            let _connection_permit = connection_permit;
            if let Err(err) = handle_connection(stream, &server) {
                eprintln!("morph hub request failed: {err:#}");
            }
        });
    }
    Ok(())
}

impl HubStore {
    fn load_or_create(path: PathBuf, pubkey: &str, network: MorphNetwork) -> Result<Self> {
        let requested_pubkey = canonical_pubkey(pubkey)?;
        let state_file_exists = path.exists();
        let state = if state_file_exists {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read hub state {}", path.display()))?;
            let persisted: PersistedHubState = serde_json::from_str(&raw).with_context(|| {
                let backup_hint = latest_state_backup(&path).map_or_else(
                    || "no backup file was found next to the state file".to_string(),
                    |backup| {
                        format!(
                            "latest backup candidate is {}; inspect it before deleting or replacing the state file",
                            backup.display()
                        )
                    },
                );
                format!(
                    "failed to parse hub state {}; {backup_hint}",
                    path.display()
                )
            })?;
            HubRuntimeState::from_persisted(persisted)?
        } else {
            let node_id = node_id_from_pubkey(&requested_pubkey)?;
            HubRuntimeState {
                pubkey: requested_pubkey.clone(),
                peer_pubkeys: BTreeMap::new(),
                node: MorphNodeState::new(node_id, network)?,
                conditional_batches: BTreeMap::new(),
                multi_asset_packages: BTreeMap::new(),
                root_fundings: BTreeMap::new(),
                events: Vec::new(),
            }
        };
        ensure!(
            state.pubkey == requested_pubkey,
            "hub state pubkey {} does not match --pubkey {}",
            state.pubkey,
            requested_pubkey
        );
        ensure!(
            state.node.network == network,
            "hub state network {} does not match --network {}",
            network_label(state.node.network),
            network_label(network)
        );
        let next_event_id = state
            .events
            .iter()
            .map(|event| event.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let store = Self {
            path,
            state,
            next_event_id,
        };
        if !state_file_exists {
            store.persist()?;
        }
        Ok(store)
    }

    fn restore_preview(&self, persisted: PersistedHubState) -> Result<RestorePreview> {
        let (candidate_state, ignored_completed_flows, allowed, warnings) =
            self.restore_candidate_state(persisted)?;
        let candidate_store = self.with_state(candidate_state);
        let current = RestoreStateSummary::from_runtime(&self.state);
        let candidate = RestoreStateSummary::from_runtime(&candidate_store.state);
        let confirmation_hash = restore_confirmation_hash(
            &self.persisted()?,
            &candidate_store.persisted()?,
            allowed,
            &ignored_completed_flows,
            &warnings,
        )?;
        Ok(RestorePreview {
            confirmation_hash,
            allowed,
            current,
            candidate,
            ignored_completed_flows,
            warnings,
        })
    }

    fn replace(&mut self, restore: RestoreStateFileRequest) -> Result<()> {
        let preview = self.restore_preview(restore.state.clone())?;
        ensure!(preview.allowed, "{}", preview.warnings.join("; "));
        ensure!(
            restore
                .confirmation_hash
                .trim()
                .eq(&preview.confirmation_hash),
            "state restore confirmation_hash does not match the current preview; preview the same state file again before restoring"
        );
        let (candidate_state, ignored_flows, _, _) = self.restore_candidate_state(restore.state)?;
        let mut candidate = self.with_state(candidate_state);
        let backup_path = backup_existing_state_file(&self.path)?;
        let mut message = backup_path.map_or_else(
            || {
                "Hub state file was replaced through the API; no previous file existed to back up"
                    .to_string()
            },
            |path| {
                format!(
                    "Hub state file was replaced through the API; previous state was backed up to {}",
                    path.display()
                )
            },
        );
        if !ignored_flows.is_empty() {
            message.push_str("; ignored restored completed_flows not present in live state: ");
            message.push_str(&ignored_flows.join(", "));
        }
        candidate.push_event(EventSeverity::Critical, "state_restored", None, message)?;
        candidate.persist()?;
        *self = candidate;
        Ok(())
    }

    fn restore_candidate_state(
        &self,
        persisted: PersistedHubState,
    ) -> Result<(HubRuntimeState, Vec<&'static str>, bool, Vec<String>)> {
        let mut candidate = HubRuntimeState::from_persisted(persisted)?;
        ensure!(
            candidate.pubkey == self.state.pubkey,
            "restored hub state pubkey {} does not match running pubkey {}",
            candidate.pubkey,
            self.state.pubkey
        );
        ensure!(
            candidate.node.network == self.state.node.network,
            "restored hub state network {} does not match running network {}",
            network_label(candidate.node.network),
            network_label(self.state.node.network)
        );

        let mut warnings = Vec::new();
        let current_has_operational_records = hub_state_has_operational_records(&self.state);
        let candidate_has_operational_records = hub_state_has_operational_records(&candidate);
        if current_has_operational_records || candidate_has_operational_records {
            warnings.push(
                "state restore is limited to empty bootstrap state until chain-anchored restore is implemented"
                    .to_string(),
            );
        }
        if candidate
            .node
            .channels
            .values()
            .any(|channel| channel.phase == Phase::Settling)
        {
            warnings.push(
                "state restore refuses settling channels because restored state cannot be chain-anchored"
                    .to_string(),
            );
        }

        let attempted_completed_flows = candidate.node.completed_flows.clone();
        candidate.node.completed_flows = candidate
            .node
            .completed_flows
            .intersection(&self.state.node.completed_flows)
            .copied()
            .collect();
        let ignored_completed_flows = attempted_completed_flows
            .difference(&candidate.node.completed_flows)
            .copied()
            .map(flow_label)
            .collect::<Vec<_>>();
        if !ignored_completed_flows.is_empty() {
            warnings.push(format!(
                "restored completed_flows not present in live state will be ignored: {}",
                ignored_completed_flows.join(", ")
            ));
        }

        Ok((
            candidate,
            ignored_completed_flows,
            warnings.is_empty(),
            warnings,
        ))
    }

    fn with_state(&self, state: HubRuntimeState) -> Self {
        Self {
            path: self.path.clone(),
            state,
            next_event_id: self.next_event_id,
        }
    }

    fn view(
        &self,
        rpc: RpcView,
        security: HubSecurityView,
        watchtower: WatchtowerView,
    ) -> Result<HubView> {
        let child_factories = self
            .state
            .node
            .factories
            .values()
            .flat_map(|factory| {
                factory
                    .materialised_child_channels
                    .iter()
                    .map(move |channel_id| (*channel_id, factory.factory_id))
            })
            .collect::<BTreeMap<_, _>>();
        Ok(HubView {
            pubkey: self.state.pubkey.clone(),
            node_id: hex_prefixed(&self.state.node.node_id),
            network: network_label(self.state.node.network),
            state_path: self.path.display().to_string(),
            rpc,
            security,
            model: hub_model_view(),
            provenance: local_state_provenance(),
            watchtower,
            peers: self
                .state
                .node
                .peers
                .values()
                .map(|peer| peer_view(peer, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            channels: self
                .state
                .node
                .channels
                .values()
                .map(|channel| {
                    channel_view(
                        channel,
                        child_factories.get(&channel.channel_id).copied(),
                        &self.state.peer_pubkeys,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            invoices: self
                .state
                .node
                .invoices
                .records()
                .map(|invoice| invoice_view(invoice, self.state.node.node_id, &self.state.pubkey))
                .collect(),
            factories: self
                .state
                .node
                .factories
                .values()
                .map(|factory| {
                    factory_view(
                        factory,
                        self.state.node.node_id,
                        &self.state.pubkey,
                        &self.state.peer_pubkeys,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            conditional_batches: self.state.conditional_batches.values().cloned().collect(),
            multi_asset_packages: self
                .state
                .multi_asset_packages
                .values()
                .rev()
                .take(MAX_MULTI_ASSET_PACKAGE_VIEWS)
                .map(|entry| entry.summary.clone())
                .collect(),
            multi_asset_package_count: self.state.multi_asset_packages.len(),
            root_fundings: self
                .state
                .root_fundings
                .values()
                .map(|entry| entry.summary.clone())
                .collect(),
            events: self.state.events.iter().map(event_view).collect(),
            required_flows: MorphNodeState::required_business_flows()
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
            completed_flows: self
                .state
                .node
                .completed_flows
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
            missing_flows: self
                .state
                .node
                .missing_business_flows()
                .iter()
                .copied()
                .map(flow_label)
                .collect(),
        })
    }

    fn persisted(&self) -> Result<PersistedHubState> {
        Ok(PersistedHubState {
            pubkey: self.state.pubkey.clone(),
            network: self.state.node.network,
            peers: self
                .state
                .node
                .peers
                .values()
                .map(|peer| persisted_peer(peer, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            channels: self
                .state
                .node
                .channels
                .values()
                .map(|channel| persisted_channel(channel, &self.state.peer_pubkeys))
                .collect::<Result<Vec<_>>>()?,
            factories: self
                .state
                .node
                .factories
                .values()
                .map(|factory| {
                    persisted_factory(
                        factory,
                        self.state.node.node_id,
                        &self.state.pubkey,
                        &self.state.peer_pubkeys,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
            conditional_batches: self.state.conditional_batches.values().cloned().collect(),
            multi_asset_packages: self
                .state
                .multi_asset_packages
                .values()
                .map(|entry| entry.package.clone())
                .collect(),
            root_fundings: self
                .state
                .root_fundings
                .values()
                .map(|entry| entry.collection.clone())
                .collect(),
            invoices: self.state.node.invoices.records().cloned().collect(),
            completed_flows: self.state.node.completed_flows.iter().copied().collect(),
            events: self.state.events.clone(),
        })
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let persisted = self.persisted()?;
        let data = serde_json::to_vec_pretty(&persisted)?;
        write_private_file_atomic(&self.path, &data)?;
        Ok(())
    }

    fn push_event(
        &mut self,
        severity: EventSeverity,
        event: impl Into<String>,
        subject_id: Option<Bytes32>,
        message: impl Into<String>,
    ) -> Result<()> {
        let id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);
        self.state.events.insert(
            0,
            HubEvent {
                id,
                severity,
                event: event.into(),
                subject_id,
                message: message.into(),
                created_at_unix: now_unix()?,
            },
        );
        self.state.events.truncate(MAX_EVENTS);
        Ok(())
    }
}

impl HubRuntimeState {
    fn from_persisted(persisted: PersistedHubState) -> Result<Self> {
        let pubkey = canonical_pubkey(&persisted.pubkey)?;
        let mut peer_pubkeys = BTreeMap::new();
        let mut node = MorphNodeState::new(node_id_from_pubkey(&pubkey)?, persisted.network)?;
        for peer in persisted.peers {
            let pubkey = canonical_pubkey(&peer.pubkey)?;
            let node_id = node_id_from_pubkey(&pubkey)?;
            ensure!(
                node_id != node.node_id,
                "peer pubkey must not be local pubkey"
            );
            node.connect_peer(MorphPeer {
                node_id,
                alias: peer.alias,
            })?;
            peer_pubkeys.insert(node_id, pubkey);
        }
        for persisted_channel in persisted.channels {
            let counterparty_pubkey = canonical_pubkey(&persisted_channel.counterparty_pubkey)?;
            let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
            ensure!(
                counterparty_node_id != node.node_id,
                "channel counterparty pubkey must not be local pubkey"
            );
            if !node.peers.contains_key(&counterparty_node_id) {
                node.connect_peer(MorphPeer {
                    node_id: counterparty_node_id,
                    alias: counterparty_pubkey.clone(),
                })?;
            }
            peer_pubkeys.insert(counterparty_node_id, counterparty_pubkey);
            let channel = MorphChannelRecord {
                channel_id: parse_bytes32("channel_id", &persisted_channel.channel_id)?,
                counterparty_node_id,
                funding_epoch: persisted_channel.funding_epoch,
                funding_context_id: parse_bytes32(
                    "funding_context_id",
                    &persisted_channel.funding_context_id,
                )?,
                state_number: persisted_channel.state_number,
                phase: persisted_channel.phase,
                balances: persisted_channel.balances,
                sponsor_budget: persisted_channel.sponsor_budget,
            };
            node.open_channel(channel)?;
        }
        for persisted_factory in persisted.factories {
            let participant_pubkeys = persisted_factory
                .participant_pubkeys
                .iter()
                .map(|value| canonical_pubkey(value))
                .collect::<Result<Vec<_>>>()?;
            let participant_node_ids = participant_pubkeys
                .iter()
                .map(|participant_pubkey| node_id_from_pubkey(participant_pubkey))
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                participant_node_ids.len() == participant_pubkeys.len(),
                "factory participant pubkeys must be unique"
            );
            ensure!(
                participant_node_ids.contains(&node.node_id),
                "factory participant_pubkeys must include local pubkey"
            );
            for participant_pubkey in participant_pubkeys {
                let participant_node_id = node_id_from_pubkey(&participant_pubkey)?;
                if participant_node_id != node.node_id {
                    peer_pubkeys.insert(participant_node_id, participant_pubkey);
                }
            }
            let materialised_child_channels = persisted_factory
                .materialised_child_channels
                .iter()
                .map(|value| parse_bytes32("materialised_child_channel", value))
                .collect::<Result<BTreeSet<_>>>()?;
            let factory = MorphFactoryRecord {
                factory_id: parse_bytes32("factory_id", &persisted_factory.factory_id)?,
                participant_node_ids,
                update_number: persisted_factory.update_number,
                reserve_balances: persisted_factory.reserve_balances,
                materialised_child_channels,
            };
            node.open_factory(factory)?;
        }
        let mut conditional_batches = BTreeMap::new();
        for package in persisted.conditional_batches {
            package.validate()?;
            let batch_id = parse_bytes32("batch_id", &package.batch_id)?;
            ensure!(
                conditional_batches.insert(batch_id, package).is_none(),
                "conditional batch ids must be unique"
            );
        }
        for invoice in persisted.invoices {
            node.invoices.insert_stored(invoice)?;
        }
        let mut multi_asset_packages = BTreeMap::new();
        ensure!(
            persisted.multi_asset_packages.len() <= MAX_MULTI_ASSET_RECOVERY_PACKAGES,
            "too many multi-asset recovery packages"
        );
        for package in persisted.multi_asset_packages {
            let summary = package.validate()?;
            let key = (
                parse_bytes32("channel_id", &summary.channel_id)?,
                parse_bytes32("funding_context_id", &summary.funding_context_id)?,
                summary.state_number.parse::<u64>()?,
            );
            ensure!(
                multi_asset_packages
                    .insert(key, HubMultiAssetPackage { package, summary })
                    .is_none(),
                "multi-asset funding-context state numbers must be unique"
            );
        }
        ensure!(
            persisted.root_fundings.len() <= MAX_ROOT_FUNDINGS,
            "too many root funding proposals"
        );
        let mut root_fundings = BTreeMap::new();
        for collection in persisted.root_fundings {
            let summary = collection.summary()?;
            ensure!(
                collection
                    .draft
                    .participants
                    .iter()
                    .any(|key| key.trim_start_matches("0x") == pubkey),
                "root funding proposal is not owned by this Hub identity"
            );
            let id = parse_bytes32(
                "root funding transaction hash",
                &summary.root.transaction_hash,
            )?;
            ensure!(
                root_fundings
                    .insert(
                        id,
                        HubRootFunding {
                            collection,
                            summary
                        }
                    )
                    .is_none(),
                "duplicate root funding transaction hash"
            );
        }
        node.completed_flows = persisted.completed_flows.into_iter().collect();
        Ok(Self {
            pubkey,
            peer_pubkeys,
            node,
            conditional_batches,
            multi_asset_packages,
            root_fundings,
            events: persisted.events,
        })
    }
}

fn handle_connection(mut stream: TcpStream, server: &HubServer) -> Result<()> {
    stream
        .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
        .context("failed to set Morph Hub request read timeout")?;
    stream
        .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
        .context("failed to set Morph Hub response write timeout")?;
    let deadline = Instant::now()
        .checked_add(REQUEST_TOTAL_TIMEOUT)
        .ok_or_else(|| anyhow!("Morph Hub request deadline exceeds platform clock range"))?;
    let mut reader =
        RequestReader::with_deadline(&mut stream, deadline, Some(set_tcp_stream_read_timeout));
    let (mut request, content_length) = read_request_head_from_reader(&mut reader)?;
    if request.method != "OPTIONS" && (request.path.starts_with("/api/") || request.path == "/api")
    {
        let request_id = server.next_request_id();
        if let Some(response) = server.auth_failure_response(
            &request,
            request_auth_scope(&request.method, &request.path),
            &request_id,
        ) {
            drop(reader);
            write_response(
                &mut stream,
                with_header(response, "X-Morph-Hub-Request-Id", request_id),
                server.cors_origin.as_deref(),
            )?;
            return Ok(());
        }
    }
    if (request.path.starts_with("/api/") || request.path == "/api")
        && matches!(request.method.as_str(), "POST" | "PUT")
    {
        read_request_body(&mut reader, &mut request, content_length)?;
    }
    drop(reader);
    if request.method == "GET" && request.path == "/api/events" {
        server.stream_events(&request, &mut stream)?;
        return Ok(());
    }
    let response = server.route(request);
    write_response(&mut stream, response, server.cors_origin.as_deref())?;
    Ok(())
}

impl HubServer {
    fn route(&self, request: HttpRequest) -> HttpResponse {
        let request_id = self.next_request_id();
        let response = match self.route_result(request, &request_id) {
            Ok(response) => response,
            Err(err) => {
                eprintln!("morph hub request {request_id} failed: {err:#}");
                api_error_response(
                    400,
                    "Bad Request",
                    "invalid_request",
                    public_api_error_message(&err),
                    &request_id,
                )
            }
        };
        with_header(response, "X-Morph-Hub-Request-Id", request_id)
    }

    fn route_result(&self, request: HttpRequest, request_id: &str) -> Result<HttpResponse> {
        if request.method == "OPTIONS" {
            return Ok(empty_response(204, "No Content"));
        }
        if request.path.starts_with("/api/") || request.path == "/api" {
            self.route_api(request, request_id)
        } else {
            self.route_static(request)
        }
    }

    fn route_api(&self, request: HttpRequest, request_id: &str) -> Result<HttpResponse> {
        let required_scope = request_auth_scope(&request.method, &request.path);
        if let Some(response) = self.auth_failure_response(&request, required_scope, request_id) {
            return Ok(response);
        }
        if matches!(request.method.as_str(), "POST" | "PUT")
            && let Some(response) = self.rate_limit_failure_response(request_id)
        {
            return Ok(response);
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/health") | ("GET", "/api/state") => self.state_response(),
            ("GET", path) if path.starts_with("/api/multi-asset-packages/") => {
                let requested = path.trim_start_matches("/api/multi-asset-packages/");
                let id = parse_bytes32("package_id", requested)?;
                let id = hex_prefixed(&id);
                let store = self.store_lock()?;
                let entry = store.state.multi_asset_packages.values().find(|entry| entry.summary.package_id == id)
                    .ok_or_else(|| anyhow!("multi-asset recovery package not found"))?;
                Ok(json_response(200, "OK", &entry.package))
            }
            ("GET",path) if path.starts_with("/api/root-fundings/") => {
                let rest=path.strip_prefix("/api/root-fundings/").ok_or_else(||anyhow!("invalid root funding path"))?;
                let (requested,export)=rest.strip_suffix("/export").map_or((rest,false),|id|(id,true));
                let id=parse_bytes32("root funding transaction hash",requested)?;
                ensure!(hex_prefixed(&id)==requested,"root funding id must be canonical lowercase hex");
                let store=self.store_lock()?;
                let entry=store.state.root_fundings.get(&id).ok_or_else(||anyhow!("root funding proposal not found"))?;
                if export {Ok(json_response(200,"OK",&entry.collection.export()?))}
                else {Ok(json_response(200,"OK",&entry.collection))}
            }
            ("GET", "/api/state-file") => {
                let store = self.store_lock()?;
                let persisted = store.persisted()?;
                Ok(json_response(200, "OK", &persisted))
            }
            ("POST", "/api/state-file/preview") => {
                if !self.allow_state_restore {
                    return Ok(api_error_response(
                        403,
                        "Forbidden",
                        "state_restore_disabled",
                        "state restore is disabled; restart Morph Hub with --allow-state-restore to enable this write path",
                        request_id,
                    ));
                }
                let persisted: PersistedHubState = parse_body(&request.body)?;
                let store = self.store_lock()?;
                let preview = store.restore_preview(persisted)?;
                Ok(json_response(200, "OK", &preview))
            }
            ("PUT", "/api/state-file") => {
                if !self.allow_state_restore {
                    return Ok(api_error_response(
                        403,
                        "Forbidden",
                        "state_restore_disabled",
                        "state restore is disabled; restart Morph Hub with --allow-state-restore to enable this write path",
                        request_id,
                    ));
                }
                let restore: RestoreStateFileRequest = parse_body(&request.body)?;
                let rpc = self.rpc_view();
                let security = self.security_view();
                let watchtower = self.watchtower_view();
                let mut store = self.store_lock()?;
                store.replace(restore)?;
                let view = store.view(rpc, security, watchtower)?;
                Ok(json_response(200, "OK", &view))
            }
            ("POST", "/api/peers") => self.mutate(request_id, |store| {
                let body: ConnectPeerRequest = parse_body(&request.body)?;
                let pubkey = canonical_pubkey(&body.pubkey)?;
                let node_id = node_id_from_pubkey(&pubkey)?;
                ensure!(
                    node_id != store.state.node.node_id,
                    "peer pubkey must not be local pubkey"
                );
                ensure!(
                    !body.alias.trim().is_empty(),
                    "peer alias must not be empty"
                );
                store.state.node.connect_peer(MorphPeer {
                    node_id,
                    alias: body.alias.trim().to_string(),
                })?;
                store.state.peer_pubkeys.insert(node_id, pubkey);
                store.push_event(
                    EventSeverity::Info,
                    "peer_connected",
                    Some(node_id),
                    "Peer added to the local node state",
                )?;
                Ok(())
            }),
            ("POST", "/api/invoices") => self.mutate(request_id, |store| {
                let payee_signing_key = self.invoice_signing_key.as_ref().ok_or_else(|| {
                    anyhow!(
                        "invoice signing is disabled; restart Morph Hub with --invoice-private-key to create signed invoices"
                    )
                })?;
                let body: CreateInvoiceRequest = parse_body(&request.body)?;
                ensure!(
                    body.expiry_secs > 0,
                    "expiry_secs must be greater than zero"
                );
                ensure!(
                    body.expiry_secs <= MAX_INVOICE_EXPIRY_SECS,
                    "expiry_secs must be at most {MAX_INVOICE_EXPIRY_SECS} seconds"
                );
                let created_at_unix = now_unix()?;
                let expires_at_unix = created_at_unix
                    .checked_add(body.expiry_secs)
                    .context("invoice expiry overflows u64")?;
                let payment_preimage = body
                    .payment_preimage
                    .as_deref()
                    .map(|value| parse_bytes32("payment_preimage", value))
                    .transpose()?;
                let payment_hash = body
                    .payment_hash
                    .as_deref()
                    .map(|value| parse_bytes32("payment_hash", value))
                    .transpose()?;
                ensure!(
                    payment_preimage.is_some() ^ payment_hash.is_some(),
                    "set exactly one of payment_preimage or payment_hash"
                );
                let channel_id = body
                    .channel_id
                    .as_deref()
                    .map(|value| parse_bytes32("channel_id", value))
                    .transpose()?;
                let asset = parse_asset(body.asset)?;
                let stored = store.state.node.create_invoice(NewMorphInvoice {
                    network: store.state.node.network,
                    payee_node_id: store.state.node.node_id,
                    channel_id,
                    amount: parse_amount_for_asset("amount", &body.amount, &asset)?,
                    asset,
                    created_at_unix,
                    expires_at_unix,
                    payment_preimage,
                    payment_hash,
                    description: body.description.trim().to_string(),
                }, payee_signing_key)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_created",
                    Some(stored.invoice.invoice_id),
                    "Invoice created by morph-core",
                )?;
                Ok(())
            }),
            ("POST", "/api/invoices/decode") => self.mutate(request_id, |store| {
                let body: DecodeInvoiceRequest = parse_body(&request.body)?;
                let stored = store
                    .state
                    .node
                    .receive_decoded_invoice(body.encoded_invoice.trim(), now_unix()?)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_received",
                    Some(stored.invoice.invoice_id),
                    "Invoice decoded and marked as received",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/invoices/") => {
                self.route_invoice_action(path, &request.body, request_id)
            }
            ("POST", "/api/channels") => self.mutate(request_id, |store| {
                let body: OpenChannelRequest = parse_body(&request.body)?;
                let counterparty_pubkey = canonical_pubkey(&body.counterparty_pubkey)?;
                let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
                ensure_peer(
                    &mut store.state,
                    &counterparty_pubkey,
                    counterparty_node_id,
                    body.counterparty_alias.as_deref(),
                )?;
                let channel = channel_from_request(
                    &body.channel_id,
                    counterparty_node_id,
                    &body.funding_context_id,
                    &body.local,
                    &body.remote,
                    body.pending.as_deref(),
                    body.sponsor_budget,
                    body.asset,
                )?;
                let channel_id = channel.channel_id;
                store.state.node.open_channel(channel)?;
                store.push_event(
                    EventSeverity::Info,
                    "channel_opened",
                    Some(channel_id),
                    "Channel opened in the Morph node state",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/channels/") => {
                self.route_channel_action(path, &request.body, request_id)
            }
            ("POST", "/api/conditional-batches") => self.mutate(request_id, |store| {
                let package: StoredConditionalBatchPackage = parse_body(&request.body)?;
                package.validate()?;
                let batch_id = parse_bytes32("batch_id", &package.batch_id)?;
                let channel_id = parse_bytes32("channel_id", &package.channel_id)?;
                let funding_context_id =
                    parse_bytes32("funding_context_id", &package.funding_context_id)?;
                let channel = store
                    .state
                    .node
                    .channels
                    .get(&channel_id)
                    .ok_or_else(|| anyhow!("conditional package channel is not open"))?;
                ensure!(
                    channel.funding_context_id == funding_context_id,
                    "conditional package funding context is stale or unknown"
                );
                ensure!(
                    channel.state_number == package.state_number,
                    "conditional package state number must match the current channel state"
                );
                if let Some(existing) = store.state.conditional_batches.get(&batch_id) {
                    ensure!(
                        existing == &package,
                        "conditional batch id already exists with different contents"
                    );
                    return Ok(());
                }
                store.state.conditional_batches.insert(batch_id, package);
                store.push_event(
                    EventSeverity::Warning,
                    "conditional_batch_imported",
                    Some(batch_id),
                    "Validated conditional force-resolution package stored for watchtower recovery",
                )?;
                Ok(())
            }),
            ("POST","/api/root-fundings") => self.mutate(request_id,|store| {
                let draft:RootFundingDraft=parse_body(&request.body)?;
                let collection=RootFundingCollection::new(draft)?;
                let local=format!("0x{}",store.state.pubkey);
                ensure!(collection.draft.participants.contains(&local),"root funding participants do not include this Hub identity");
                let peer=collection.draft.participants.iter().find(|key|**key!=local).ok_or_else(||anyhow!("missing root funding peer"))?;
                ensure!(store.state.peer_pubkeys.values().any(|pubkey|format!("0x{pubkey}")==*peer),"root funding counterparty must be a known peer");
                let summary=collection.summary()?;
                let id=parse_bytes32("root funding transaction hash",&summary.root.transaction_hash)?;
                if let Some(existing)=store.state.root_fundings.get(&id) {
                    ensure!(existing.collection.draft==collection.draft,"root funding id already holds another immutable draft");return Ok(());
                }
                ensure!(store.state.root_fundings.len()<MAX_ROOT_FUNDINGS,"root funding proposal store is full");
                store.state.root_fundings.insert(id,HubRootFunding {collection,summary});
                store.push_event(EventSeverity::Info,"root_funding_proposed",Some(id),"Root funding proposal retained for participant review")?;Ok(())
            }),
            ("POST",path) if path.starts_with("/api/root-fundings/") && path.ends_with("/signatures") => self.mutate(request_id,|store| {
                let requested=path.strip_prefix("/api/root-fundings/").and_then(|rest|rest.strip_suffix("/signatures")).ok_or_else(||anyhow!("invalid root receipt path"))?;
                let id=parse_bytes32("root funding transaction hash",requested)?;
                ensure!(hex_prefixed(&id)==requested,"root funding id must be canonical lowercase hex");
                let message:RootReceiptRequest=parse_body(&request.body)?;
                let entry=store.state.root_fundings.get_mut(&id).ok_or_else(||anyhow!("root funding proposal not found"))?;
                if !entry.collection.add(message.target,message.receipt)? {return Ok(());}
                entry.summary=entry.collection.summary()?;
                store.push_event(EventSeverity::Info,"root_funding_signature_received",Some(id),"Verified participant funding receipt retained")?;Ok(())
            }),
            ("POST", "/api/multi-asset-packages") => self.mutate(request_id, |store| {
                let package: StoredMultiAssetPackage = parse_body(&request.body)?;
                let summary = package.validate()?;
                let channel_id = parse_bytes32("channel_id", &summary.channel_id)?;
                let funding_context_id = parse_bytes32("funding_context_id", &summary.funding_context_id)?;
                let state_number = summary.state_number.parse::<u64>()?;
                let channel = store.state.node.channels.get(&channel_id).ok_or_else(|| anyhow!("multi-asset package channel is not open"))?;
                ensure!(summary.vaults_bound && summary.phase == "settling", "recovery import requires a bound settling state");
                ensure!(channel.funding_context_id == funding_context_id, "multi-asset package funding context is stale or unknown");
                ensure!(channel.state_number == state_number, "multi-asset package state must match the current channel state");
                let peer = store.state.peer_pubkeys.get(&channel.counterparty_node_id).ok_or_else(|| anyhow!("multi-asset counterparty public key is missing"))?;
                let mut expected_signers = [canonical_pubkey(&store.state.pubkey)?, canonical_pubkey(peer)?];
                expected_signers.sort();
                let mut actual_signers = [canonical_pubkey(summary.signer_pubkeys[0].trim_start_matches("0x"))?, canonical_pubkey(summary.signer_pubkeys[1].trim_start_matches("0x"))?];
                actual_signers.sort();
                ensure!(expected_signers == actual_signers, "multi-asset package signers do not match the channel participants");
                let key = (channel_id, funding_context_id, state_number);
                if let Some(existing) = store.state.multi_asset_packages.get(&key) {
                    ensure!(existing.package == package, "conflicting signed multi-asset states share a funding context and state number");
                    return Ok(());
                }
                ensure!(store.state.multi_asset_packages.len() < MAX_MULTI_ASSET_RECOVERY_PACKAGES, "multi-asset recovery store is full; archive retained packages before importing more");
                store.state.multi_asset_packages.insert(key, HubMultiAssetPackage { package, summary });
                store.push_event(EventSeverity::Warning, "multi_asset_recovery_imported", Some(channel_id), "Validated multi-asset unilateral recovery package stored")?;
                Ok(())
            }),
            ("POST", "/api/factories") => self.mutate(request_id, |store| {
                let body: OpenFactoryRequest = parse_body(&request.body)?;
                let factory_id = parse_bytes32("factory_id", &body.factory_id)?;
                ensure!(
                    !body.participant_pubkeys.is_empty(),
                    "factory requires at least one participant"
                );
                let participant_pubkeys = body
                    .participant_pubkeys
                    .iter()
                    .map(|value| canonical_pubkey(value))
                    .collect::<Result<Vec<_>>>()?;
                let participant_node_ids = participant_pubkeys
                    .iter()
                    .map(|pubkey| node_id_from_pubkey(pubkey))
                    .collect::<Result<BTreeSet<_>>>()?;
                ensure!(
                    participant_node_ids.len() == participant_pubkeys.len(),
                    "factory participant pubkeys must be unique"
                );
                ensure!(
                    participant_node_ids.contains(&store.state.node.node_id),
                    "factory participant_pubkeys must include local pubkey"
                );
                for pubkey in &participant_pubkeys {
                    let node_id = node_id_from_pubkey(pubkey)?;
                    if node_id != store.state.node.node_id {
                        store.state.peer_pubkeys.insert(node_id, pubkey.clone());
                    }
                }
                let asset = parse_asset(body.asset)?;
                let factory = MorphFactoryRecord {
                    factory_id,
                    participant_node_ids,
                    update_number: 0,
                    reserve_balances: vec![MorphAssetBalance {
                        local: parse_amount_for_asset("reserve", &body.reserve, &asset)?,
                        asset,
                        remote: 0,
                        pending: 0,
                    }],
                    materialised_child_channels: BTreeSet::new(),
                };
                store.state.node.open_factory(factory)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_opened",
                    Some(factory_id),
                    "Factory opened in the Morph node state",
                )?;
                Ok(())
            }),
            ("POST", path) if path.starts_with("/api/factories/") => {
                self.route_factory_action(path, &request.body, request_id)
            }
            _ => Ok(api_error_response(
                404,
                "Not Found",
                "unknown_endpoint",
                "unknown Morph hub endpoint",
                request_id,
            )),
        }
    }

    fn stream_events(&self, request: &HttpRequest, stream: &mut TcpStream) -> Result<()> {
        let request_id = self.next_request_id();
        if let Some(response) = self.auth_failure_response(request, AuthScope::Read, &request_id) {
            write_response(
                stream,
                with_header(response, "X-Morph-Hub-Request-Id", request_id),
                self.cors_origin.as_deref(),
            )?;
            return Ok(());
        }
        let Some(_sse_permit) = try_acquire_counter(
            Arc::clone(&self.active_sse_streams),
            MAX_CONCURRENT_SSE_STREAMS,
        ) else {
            write_response(
                stream,
                with_header(
                    api_error_response(
                        429,
                        "Too Many Requests",
                        "too_many_event_streams",
                        "too many concurrent Morph Hub event streams",
                        &request_id,
                    ),
                    "X-Morph-Hub-Request-Id",
                    request_id,
                ),
                self.cors_origin.as_deref(),
            )?;
            return Ok(());
        };

        let mut last_event_id =
            parse_last_event_id(request)?.unwrap_or_else(|| self.latest_event_id());
        write_sse_headers(stream, self.cors_origin.as_deref(), &request_id)?;

        let mut last_heartbeat = Instant::now();
        loop {
            let events = self.events_after(last_event_id);
            for event in events {
                last_event_id = event.id;
                if write_sse_event(stream, &event).is_err() {
                    return Ok(());
                }
                last_heartbeat = Instant::now();
            }

            if last_heartbeat.elapsed() >= EVENT_STREAM_HEARTBEAT_INTERVAL {
                if write!(stream, ": keepalive\n\n").is_err() {
                    return Ok(());
                }
                if stream.flush().is_err() {
                    return Ok(());
                }
                last_heartbeat = Instant::now();
            }

            thread::sleep(EVENT_STREAM_POLL_INTERVAL);
        }
    }

    fn latest_event_id(&self) -> u64 {
        let Ok(store) = self.store.lock() else {
            eprintln!("morph hub event stream failed: hub state lock is poisoned");
            return 0;
        };
        store.state.events.first().map_or(0, |event| event.id)
    }

    fn events_after(&self, last_event_id: u64) -> Vec<HubEvent> {
        let Ok(store) = self.store.lock() else {
            eprintln!("morph hub event stream failed: hub state lock is poisoned");
            return Vec::new();
        };
        let mut events = store
            .state
            .events
            .iter()
            .filter(|event| event.id > last_event_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by_key(|event| event.id);
        events
    }

    fn route_invoice_action(
        &self,
        path: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<HttpResponse> {
        let (invoice_id, action) = split_action_path(path, "/api/invoices/")?;
        match action {
            "receive" => self.mutate(request_id, |store| {
                store.state.node.receive_invoice(&invoice_id, now_unix()?)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_received",
                    Some(invoice_id),
                    "Invoice marked as received",
                )?;
                Ok(())
            }),
            "settle" => self.mutate(request_id, |store| {
                let body: SettleInvoiceRequest = parse_body(body)?;
                let preimage = parse_bytes32("payment_preimage", &body.payment_preimage)?;
                store
                    .state
                    .node
                    .settle_invoice(&invoice_id, preimage, now_unix()?)?;
                store.push_event(
                    EventSeverity::Info,
                    "invoice_settled",
                    Some(invoice_id),
                    "Invoice settled with a matching preimage",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown invoice action" }),
            )),
        }
    }

    fn route_channel_action(
        &self,
        path: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<HttpResponse> {
        let (channel_id, action) = split_action_path(path, "/api/channels/")?;
        match action {
            "splice" => self.mutate(request_id, |store| {
                let body: SpliceChannelRequest = parse_body(body)?;
                let new_funding_context_id =
                    parse_bytes32("new_funding_context_id", &body.new_funding_context_id)?;
                store.state.node.splice_channel(
                    &channel_id,
                    body.new_funding_epoch,
                    new_funding_context_id,
                )?;
                store.push_event(
                    EventSeverity::Warning,
                    "channel_spliced",
                    Some(channel_id),
                    "Channel funding context advanced",
                )?;
                Ok(())
            }),
            "publish" => self.mutate(request_id, |store| {
                let body: PublishStateRequest = parse_body(body)?;
                let funding_context_id =
                    parse_bytes32("funding_context_id", &body.funding_context_id)?;
                store.state.node.publish_state(
                    &channel_id,
                    funding_context_id,
                    body.state_number,
                )?;
                store.push_event(
                    EventSeverity::Warning,
                    "state_published",
                    Some(channel_id),
                    "Latest channel state published",
                )?;
                Ok(())
            }),
            "finalise" => self.mutate(request_id, |store| {
                ensure!(body.is_empty(), "finalise request body must be empty");
                store.state.node.finalise_channel(&channel_id)?;
                store.push_event(
                    EventSeverity::Info,
                    "channel_finalised",
                    Some(channel_id),
                    "Settling channel finalised",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown channel action" }),
            )),
        }
    }

    fn route_factory_action(
        &self,
        path: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<HttpResponse> {
        let (factory_id, action) = split_action_path(path, "/api/factories/")?;
        match action {
            "advance" => self.mutate(request_id, |store| {
                let body: AdvanceFactoryRequest = parse_body(body)?;
                store
                    .state
                    .node
                    .advance_factory(&factory_id, body.new_update_number)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_advanced",
                    Some(factory_id),
                    "Factory update number advanced",
                )?;
                Ok(())
            }),
            "materialise-child" => self.mutate(request_id, |store| {
                let body: MaterialiseChildRequest = parse_body(body)?;
                let counterparty_pubkey = canonical_pubkey(&body.counterparty_pubkey)?;
                let counterparty_node_id = node_id_from_pubkey(&counterparty_pubkey)?;
                ensure_peer(
                    &mut store.state,
                    &counterparty_pubkey,
                    counterparty_node_id,
                    body.counterparty_alias.as_deref(),
                )?;
                let child = channel_from_request(
                    &body.child_channel_id,
                    counterparty_node_id,
                    &body.funding_context_id,
                    &body.local,
                    &body.remote,
                    body.pending.as_deref(),
                    body.sponsor_budget,
                    body.asset,
                )?;
                let child_channel_id = child.channel_id;
                store
                    .state
                    .node
                    .materialise_child_channel(&factory_id, child)?;
                store.push_event(
                    EventSeverity::Info,
                    "factory_child_materialised",
                    Some(child_channel_id),
                    "Factory child channel materialised",
                )?;
                Ok(())
            }),
            _ => Ok(json_response(
                404,
                "Not Found",
                &json!({ "error": "unknown factory action" }),
            )),
        }
    }

    fn mutate<F>(&self, request_id: &str, f: F) -> Result<HttpResponse>
    where
        F: FnOnce(&mut HubStore) -> Result<()>,
    {
        let Some(_mutation_permit) =
            try_acquire_counter(Arc::clone(&self.active_mutations), MAX_CONCURRENT_MUTATIONS)
        else {
            return Ok(api_error_response(
                429,
                "Too Many Requests",
                "too_many_mutations",
                "too many concurrent Morph Hub mutations",
                request_id,
            ));
        };
        let rpc = self.rpc_view();
        let security = self.security_view();
        let watchtower = self.watchtower_view();
        let mut store = self.store_lock()?;
        let mut candidate = store.clone();
        f(&mut candidate)?;
        let view = candidate.view(rpc, security, watchtower)?;
        candidate.persist()?;
        *store = candidate;
        Ok(json_response(200, "OK", &view))
    }

    fn state_response(&self) -> Result<HttpResponse> {
        let rpc = self.rpc_view();
        let security = self.security_view();
        let watchtower = self.watchtower_view();
        let store = self.store_lock()?;
        let view = store.view(rpc, security, watchtower)?;
        Ok(json_response(200, "OK", &view))
    }

    fn store_lock(&self) -> Result<MutexGuard<'_, HubStore>> {
        self.store
            .lock()
            .map_err(|_| anyhow!("hub state lock is poisoned"))
    }

    fn auth_failure_response(
        &self,
        request: &HttpRequest,
        required_scope: AuthScope,
        request_id: &str,
    ) -> Option<HttpResponse> {
        let Some(token) = self.auth_token.as_ref() else {
            return (!self.allow_unauthenticated_loopback).then(|| {
                api_error_response(
                    401,
                    "Unauthorized",
                    "auth_required",
                    "Morph Hub API authentication is required; start with an auth token or explicitly allow unauthenticated loopback for local development",
                    request_id,
                )
            });
        };
        let authorised = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|value| {
                constant_time_eq(&blake2b256(value.as_bytes()), &token.secret_hash)
            })
            || request.header("x-morph-hub-token").is_some_and(|value| {
                constant_time_eq(&blake2b256(value.as_bytes()), &token.secret_hash)
            });
        if !authorised {
            return Some(api_error_response(
                401,
                "Unauthorized",
                "invalid_auth_token",
                "missing or invalid Morph Hub auth token",
                request_id,
            ));
        }
        (!token.scopes.contains(&required_scope)).then(|| {
            api_error_response(
                403,
                "Forbidden",
                "insufficient_auth_scope",
                format!(
                    "Morph Hub auth token needs the {} scope for this endpoint",
                    auth_scope_label(required_scope)
                ),
                request_id,
            )
        })
    }

    fn rate_limit_failure_response(&self, request_id: &str) -> Option<HttpResponse> {
        let Ok(mut limiter) = self.rate_limiter.lock() else {
            return Some(api_error_response(
                503,
                "Service Unavailable",
                "rate_limiter_unavailable",
                "Morph Hub rate limiter is unavailable",
                request_id,
            ));
        };
        if limiter.window_started.elapsed() >= MUTATION_RATE_LIMIT_WINDOW {
            limiter.window_started = Instant::now();
            limiter.mutating_requests = 0;
        }
        if limiter.mutating_requests >= MAX_MUTATIONS_PER_WINDOW {
            let retry_after = MUTATION_RATE_LIMIT_WINDOW
                .saturating_sub(limiter.window_started.elapsed())
                .as_secs()
                .max(1);
            return Some(with_header(
                api_error_response(
                    429,
                    "Too Many Requests",
                    "rate_limited",
                    "too many Morph Hub mutating requests; retry after the rate limit window resets",
                    request_id,
                ),
                "Retry-After",
                retry_after.to_string(),
            ));
        }
        limiter.mutating_requests += 1;
        None
    }

    fn security_view(&self) -> HubSecurityView {
        HubSecurityView {
            auth_required: self.auth_token.is_some(),
            auth_mode: if self.auth_token.is_some() {
                "scoped_bearer"
            } else {
                "explicit_unauthenticated_loopback"
            },
            auth_scopes: self
                .auth_token
                .as_ref()
                .map(|token| token.scopes.iter().copied().collect())
                .unwrap_or_default(),
            single_operator: true,
            state_restore_enabled: self.allow_state_restore,
            invoice_signing_enabled: self.invoice_signing_key.is_some(),
            cors_origin: self.cors_origin.clone(),
            max_concurrent_connections: MAX_CONCURRENT_CONNECTIONS,
            max_concurrent_mutations: MAX_CONCURRENT_MUTATIONS,
            max_concurrent_event_streams: MAX_CONCURRENT_SSE_STREAMS,
            mutation_rate_limit_per_minute: MAX_MUTATIONS_PER_WINDOW,
            max_invoice_expiry_secs: MAX_INVOICE_EXPIRY_SECS,
        }
    }

    fn next_request_id(&self) -> String {
        format!(
            "hub-{}",
            self.request_counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn rpc_view(&self) -> RpcView {
        let Some(url) = self.ckb_rpc_url.clone() else {
            return RpcView {
                status: "not_configured",
                url: None,
                tip_height: None,
                chain: None,
                message: Some("start with --ckb-rpc-url to enable live chain health".to_string()),
            };
        };
        let (view, should_refresh) = {
            let Ok(mut cache) = self.rpc_cache.lock() else {
                return RpcView {
                    status: "offline",
                    url: Some(url),
                    tip_height: None,
                    chain: None,
                    message: Some("RPC health cache is unavailable".to_string()),
                };
            };
            let (cached_view, stale) = match cache.value.as_ref().filter(|cached| cached.url == url)
            {
                Some(cached) => (
                    Some(cached.view.clone()),
                    cached.checked_at.elapsed() >= RPC_HEALTH_CACHE_TTL,
                ),
                None => (None, true),
            };
            let should_refresh = stale && !cache.refresh_in_flight;
            if should_refresh {
                cache.refresh_in_flight = true;
            }
            let view = cached_view.unwrap_or_else(|| RpcView {
                status: "degraded",
                url: Some(url.clone()),
                tip_height: None,
                chain: None,
                message: Some("CKB RPC health check is pending".to_string()),
            });
            (view, should_refresh)
        };
        if should_refresh {
            self.spawn_rpc_refresh(url);
        }
        view
    }

    fn refresh_rpc_cache(&self) {
        let Some(url) = self.ckb_rpc_url.clone() else {
            return;
        };
        let Ok(mut cache) = self.rpc_cache.lock() else {
            return;
        };
        if cache.refresh_in_flight {
            return;
        }
        cache.refresh_in_flight = true;
        drop(cache);
        self.spawn_rpc_refresh(url);
    }

    fn spawn_rpc_refresh(&self, url: String) {
        let cache = Arc::clone(&self.rpc_cache);
        thread::spawn(move || {
            let view = probe_rpc_view(url.clone());
            let Ok(mut cache) = cache.lock() else {
                return;
            };
            cache.value = Some(CachedRpcView {
                url,
                checked_at: Instant::now(),
                view,
            });
            cache.refresh_in_flight = false;
        });
    }

    fn watchtower_view(&self) -> WatchtowerView {
        let Some(path) = self.watch_alert_file.as_ref() else {
            return WatchtowerView {
                configured: false,
                alert_file: None,
                file_exists: false,
                alerts: Vec::new(),
                last_error: None,
                provenance: local_state_provenance(),
            };
        };

        let (file_exists, alerts, last_error) = self.load_watchtower_alerts_cached(path);
        WatchtowerView {
            configured: true,
            alert_file: Some(path.display().to_string()),
            file_exists,
            alerts,
            last_error,
            provenance: watchtower_alert_provenance(),
        }
    }

    fn load_watchtower_alerts_cached(
        &self,
        path: &Path,
    ) -> (bool, Vec<WatchtowerAlertView>, Option<String>) {
        let metadata = fs::metadata(path).ok();
        let modified = metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok());
        let len = metadata.as_ref().map_or(0, fs::Metadata::len);
        if let Ok(cache) = self.watch_alert_cache.lock()
            && cache.path.as_deref() == Some(path)
            && cache.modified == modified
            && cache.len == len
            && let Some(value) = &cache.value
        {
            return value.clone();
        }

        let value = load_watchtower_alerts(path);
        if let Ok(mut cache) = self.watch_alert_cache.lock() {
            cache.path = Some(path.to_path_buf());
            cache.modified = modified;
            cache.len = len;
            cache.value = Some(value.clone());
        }
        value
    }

    fn route_static(&self, request: HttpRequest) -> Result<HttpResponse> {
        ensure!(request.method == "GET", "static assets only support GET");
        let path = static_path(&self.ui_dir, &request.path)?;
        if path.exists() && path.is_file() {
            let body = fs::read(&path)
                .with_context(|| format!("failed to read static asset {}", path.display()))?;
            return Ok(HttpResponse {
                status: 200,
                reason: "OK",
                content_type: content_type(&path),
                headers: static_cache_headers(&path),
                body,
            });
        }
        let index = static_path(&self.ui_dir, "/")?;
        if index.exists() {
            return Ok(HttpResponse {
                status: 200,
                reason: "OK",
                content_type: "text/html; charset=utf-8",
                headers: static_cache_headers(&index),
                body: fs::read(index)?,
            });
        }
        Ok(json_response(
            404,
            "Not Found",
            &json!({
                "error": format!(
                    "hub UI not built at {}; run npm run build in ui/morph-hub",
                    self.ui_dir.display()
                )
            }),
        ))
    }
}

fn ensure_peer(
    state: &mut HubRuntimeState,
    pubkey: &str,
    counterparty_node_id: Bytes32,
    alias: Option<&str>,
) -> Result<()> {
    ensure!(
        counterparty_node_id != state.node.node_id,
        "counterparty pubkey must not be local pubkey"
    );
    if state.node.peers.contains_key(&counterparty_node_id) {
        state
            .peer_pubkeys
            .entry(counterparty_node_id)
            .or_insert_with(|| pubkey.to_string());
        return Ok(());
    }
    state.node.connect_peer(MorphPeer {
        node_id: counterparty_node_id,
        alias: alias
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| pubkey.to_string()),
    })?;
    state
        .peer_pubkeys
        .insert(counterparty_node_id, pubkey.to_string());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn channel_from_request(
    channel_id: &str,
    counterparty_node_id: Bytes32,
    funding_context_id: &str,
    local: &str,
    remote: &str,
    pending: Option<&str>,
    sponsor_budget: u64,
    asset: Option<AssetRequest>,
) -> Result<MorphChannelRecord> {
    let asset = parse_asset(asset)?;
    Ok(MorphChannelRecord {
        channel_id: parse_bytes32("channel_id", channel_id)?,
        counterparty_node_id,
        funding_epoch: 0,
        funding_context_id: parse_bytes32("funding_context_id", funding_context_id)?,
        state_number: 1,
        phase: Phase::Active,
        balances: vec![MorphAssetBalance {
            local: parse_amount_for_asset("local", local, &asset)?,
            remote: parse_amount_for_asset("remote", remote, &asset)?,
            pending: parse_amount_for_asset("pending", pending.unwrap_or("0"), &asset)?,
            asset,
        }],
        sponsor_budget,
    })
}

fn constant_time_eq(left: &Bytes32, right: &Bytes32) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hub_state_has_operational_records(state: &HubRuntimeState) -> bool {
    !state.node.peers.is_empty()
        || !state.node.channels.is_empty()
        || !state.node.factories.is_empty()
        || !state.conditional_batches.is_empty()
        || !state.multi_asset_packages.is_empty()
        || !state.root_fundings.is_empty()
        || state.node.invoices.records().next().is_some()
        || !state.node.completed_flows.is_empty()
}

fn split_action_path<'a>(path: &'a str, prefix: &str) -> Result<(Bytes32, &'a str)> {
    let suffix = path
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("invalid action path"))?;
    let (id, action) = suffix
        .split_once('/')
        .ok_or_else(|| anyhow!("action path must include an id and action"))?;
    Ok((parse_bytes32("id", id)?, action))
}

fn probe_rpc_view(url: String) -> RpcView {
    match CkbRpcClient::new_health_check(url.clone()).and_then(|client| client.status()) {
        Ok(status) => RpcView {
            status: if status.node.active {
                "connected"
            } else {
                "degraded"
            },
            url: Some(url),
            tip_height: status.tip.number_value().ok(),
            chain: Some(status.chain.chain),
            message: None,
        },
        Err(err) => RpcView {
            status: "offline",
            url: Some(url),
            tip_height: None,
            chain: None,
            message: Some(err.to_string()),
        },
    }
}

fn restore_confirmation_hash(
    current: &PersistedHubState,
    candidate: &PersistedHubState,
    allowed: bool,
    ignored_completed_flows: &[&'static str],
    warnings: &[String],
) -> Result<String> {
    #[derive(Serialize)]
    struct RestoreConfirmationMaterial<'a> {
        domain: &'static str,
        current: &'a PersistedHubState,
        candidate: &'a PersistedHubState,
        allowed: bool,
        ignored_completed_flows: &'a [&'static str],
        warnings: &'a [String],
    }

    let material = RestoreConfirmationMaterial {
        domain: "morph.hub.state_restore_confirmation",
        current,
        candidate,
        allowed,
        ignored_completed_flows,
        warnings,
    };
    let encoded = serde_json::to_vec(&material)
        .context("failed to serialise state restore confirmation material")?;
    Ok(hex_prefixed(&blake2b256(&encoded)))
}

fn latest_state_backup(path: &Path) -> Option<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name()?.to_str()?;
    let prefix = format!("{file_name}.bak.");
    fs::read_dir(parent)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !name.starts_with(&prefix) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((path, modified))
        })
        .max_by_key(|(_, modified)| *modified)
        .map(|(path, _)| path)
}

fn backup_existing_state_file(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("hub state path must include a file name"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_nanos();
    let backup_path = path.with_file_name(format!(
        "{file_name}.bak.{timestamp}.{}",
        std::process::id()
    ));
    let data = fs::read(path)
        .with_context(|| format!("failed to read current hub state {}", path.display()))?;
    let mut file = create_private_new_file(&backup_path)?;
    file.write_all(&data)
        .with_context(|| format!("failed to write state backup {}", backup_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync state backup {}", backup_path.display()))?;
    sync_parent_dir(&backup_path)?;
    Ok(Some(backup_path))
}

fn write_private_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("hub state path must include a file name"))?;
    let tmp_path = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp_path);
    let mut file = create_private_new_file(&tmp_path)?;
    file.write_all(data)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
    drop(file);
    fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to atomically replace hub state {}", path.display()))?;
    sync_parent_dir(path)?;
    Ok(())
}

fn create_private_new_file(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to create private file {}", path.display()))
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("failed to sync directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    ensure!(!body.is_empty(), "request body must not be empty");
    serde_json::from_slice(body).context("request body is not valid JSON")
}

fn parse_asset(asset: Option<AssetRequest>) -> Result<MorphAsset> {
    match asset.unwrap_or(AssetRequest::Ckb) {
        AssetRequest::Ckb => Ok(MorphAsset::Ckb),
        AssetRequest::Xudt { type_hash } => Ok(MorphAsset::Xudt(parse_bytes32(
            "asset.type_hash",
            &type_hash,
        )?)),
    }
}

fn parse_amount(label: &str, value: &str) -> Result<u128> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{label} must not be empty");
    let amount = value
        .parse::<u128>()
        .with_context(|| format!("{label} must be an unsigned integer"))?;
    ensure!(
        amount > 0 || label == "pending",
        "{label} must be greater than zero"
    );
    Ok(amount)
}

fn parse_amount_for_asset(label: &str, value: &str, asset: &MorphAsset) -> Result<u128> {
    let amount = parse_amount(label, value)?;
    if matches!(asset, MorphAsset::Ckb) {
        ensure!(
            amount <= u128::from(u64::MAX),
            "{label} for CKB must fit in a u64 shannon quantity"
        );
    }
    Ok(amount)
}

fn canonical_pubkey(value: &str) -> Result<String> {
    Ok(hex::encode(parse_pubkey_bytes(value)?))
}

fn node_id_from_pubkey(pubkey: &str) -> Result<Bytes32> {
    let bytes = parse_pubkey_bytes(pubkey)?;
    Ok(blake2b256(&bytes))
}

fn parse_pubkey_bytes(value: &str) -> Result<[u8; 33]> {
    let value = value.trim().to_lowercase();
    ensure!(
        !value.is_empty(),
        "pubkey must not be empty; pass a 33-byte compressed secp256k1 pubkey as 66 hex characters without 0x"
    );
    ensure!(
        !value.starts_with("0x"),
        "pubkey must be hex without 0x, matching Fiber RPC convention"
    );
    ensure!(
        value.len() == 66,
        "pubkey must be a 33-byte compressed secp256k1 pubkey encoded as 66 hex characters"
    );
    let raw = hex::decode(&value).context("pubkey is not valid hex")?;
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    ensure!(
        matches!(out[0], 0x02 | 0x03),
        "pubkey must be a compressed secp256k1 public key starting with 02 or 03"
    );
    k256::PublicKey::from_sec1_bytes(&out)
        .map_err(|_| anyhow!("pubkey is not a valid secp256k1 public key"))?;
    Ok(out)
}

fn parse_signing_key(value: &str, label: &str) -> Result<SigningKey> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{label} must not be empty");
    let raw = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{label} must be hex encoded"))?;
    ensure!(raw.len() == 32, "{label} must be 32 bytes");
    SigningKey::from_slice(&raw)
        .map_err(|err| anyhow!("{label} is not a valid secp256k1 private key: {err:?}"))
}

fn signing_key_pubkey_sec1(signing_key: &SigningKey) -> [u8; 33] {
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn parse_bytes32(label: &str, value: &str) -> Result<Bytes32> {
    let value = value.trim();
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("{label} must be 0x-prefixed"))?;
    ensure!(hex.len() == 64, "{label} must be 32 bytes");
    let raw = hex::decode(hex).with_context(|| format!("{label} is not valid hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    ensure!(
        out.iter().any(|byte| *byte != 0),
        "{label} must not be zero"
    );
    Ok(out)
}

#[cfg(test)]
fn read_request_from_reader(reader: impl Read) -> Result<HttpRequest> {
    let mut reader = RequestReader::without_deadline(reader);
    let (mut request, content_length) = read_request_head_from_reader(&mut reader)?;
    read_request_body(&mut reader, &mut request, content_length)?;
    Ok(request)
}

type ReadTimeoutSetter<R> = fn(&mut R, Duration) -> std::io::Result<()>;

struct RequestReader<R> {
    inner: BufReader<R>,
    deadline: Option<Instant>,
    timeout_setter: Option<ReadTimeoutSetter<R>>,
}

impl<R: Read> RequestReader<R> {
    #[cfg(test)]
    fn without_deadline(inner: R) -> Self {
        Self {
            inner: BufReader::new(inner),
            deadline: None,
            timeout_setter: None,
        }
    }

    fn with_deadline(
        inner: R,
        deadline: Instant,
        timeout_setter: Option<ReadTimeoutSetter<R>>,
    ) -> Self {
        Self {
            inner: BufReader::new(inner),
            deadline: Some(deadline),
            timeout_setter,
        }
    }

    fn prepare_read(&mut self) -> Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow!("Morph Hub request exceeded its total read deadline"))?;
        if let Some(set_timeout) = self.timeout_setter {
            set_timeout(self.inner.get_mut(), remaining.min(REQUEST_IO_TIMEOUT))
                .context("failed to update Morph Hub request read timeout")?;
        }
        Ok(())
    }

    fn fill_buf(&mut self) -> Result<&[u8]> {
        self.prepare_read()?;
        self.inner.fill_buf().context("failed to read HTTP line")
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }

    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            self.prepare_read()?;
            let read = self
                .inner
                .read(buf)
                .context("failed to read HTTP request body")?;
            ensure!(read > 0, "unexpected EOF while reading HTTP request body");
            buf = &mut buf[read..];
        }
        Ok(())
    }
}

fn set_tcp_stream_read_timeout(
    stream: &mut &mut TcpStream,
    timeout: Duration,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(timeout))
}

fn read_request_head_from_reader<R: Read>(
    reader: &mut RequestReader<R>,
) -> Result<(HttpRequest, usize)> {
    let (request_line, mut header_bytes) = read_limited_line(reader, MAX_REQUEST_LINE_BYTES)?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let uri = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    ensure!(parts.next().is_none(), "malformed HTTP request line");
    ensure!(
        matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "unsupported HTTP request version"
    );
    let path = uri.split('?').next().unwrap_or(&uri).to_string();

    let mut content_length = None;
    let mut headers = BTreeMap::new();
    loop {
        let (line, line_bytes) = read_limited_line(reader, MAX_REQUEST_LINE_BYTES)?;
        header_bytes = header_bytes
            .checked_add(line_bytes)
            .context("HTTP headers are too large")?;
        ensure!(
            header_bytes <= MAX_REQUEST_HEADER_BYTES,
            "HTTP headers exceed {} bytes",
            MAX_REQUEST_HEADER_BYTES
        );
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let canonical_name = name.trim().to_ascii_lowercase();
            let duplicate_message = match canonical_name.as_str() {
                "authorization" => "duplicate Authorization header".to_string(),
                "content-length" => "duplicate Content-Length header".to_string(),
                _ => format!("duplicate {canonical_name} header"),
            };
            ensure!(
                !headers.contains_key(&canonical_name),
                "{duplicate_message}"
            );
            headers.insert(canonical_name, value.trim().to_string());
            if name.eq_ignore_ascii_case("content-length") {
                ensure!(content_length.is_none(), "duplicate Content-Length header");
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .context("invalid Content-Length")?;
                ensure!(
                    parsed <= MAX_REQUEST_BODY_BYTES,
                    "request body exceeds {} bytes",
                    MAX_REQUEST_BODY_BYTES
                );
                content_length = Some(parsed);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                ensure!(
                    value.trim().eq_ignore_ascii_case("identity"),
                    "unsupported Transfer-Encoding header"
                );
            }
        }
    }

    Ok((
        HttpRequest {
            method,
            path,
            headers,
            body: Vec::new(),
        },
        content_length.unwrap_or(0),
    ))
}

fn read_request_body<R: Read>(
    reader: &mut RequestReader<R>,
    request: &mut HttpRequest,
    content_length: usize,
) -> Result<()> {
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    request.body = body;
    Ok(())
}

fn read_limited_line<R: Read>(
    reader: &mut RequestReader<R>,
    max_bytes: usize,
) -> Result<(String, usize)> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        ensure!(
            !available.is_empty(),
            "unexpected EOF while reading HTTP line"
        );
        if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
            let take = newline_index + 1;
            ensure!(
                buf.len() + take <= max_bytes,
                "HTTP line exceeds {} bytes",
                max_bytes
            );
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        ensure!(
            buf.len() + available.len() <= max_bytes,
            "HTTP line exceeds {} bytes",
            max_bytes
        );
        let take = available.len();
        buf.extend_from_slice(available);
        reader.consume(take);
    }
    let bytes = buf.len();
    let line = String::from_utf8(buf)
        .context("HTTP line is not valid UTF-8")?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    Ok((line, bytes))
}

fn write_response(
    stream: &mut TcpStream,
    response: HttpResponse,
    cors_origin: Option<&str>,
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    )?;
    if let Some(origin) = cors_origin {
        write!(
            stream,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\nAccess-Control-Allow-Headers: content-type, authorization, x-morph-hub-token\r\n"
        )?;
    }
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

fn write_sse_headers(
    stream: &mut TcpStream,
    cors_origin: Option<&str>,
    request_id: &str,
) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nX-Morph-Hub-Request-Id: {request_id}\r\nConnection: keep-alive\r\n"
    )?;
    if let Some(origin) = cors_origin {
        write!(
            stream,
            "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Headers: content-type, authorization, x-morph-hub-token\r\n"
        )?;
    }
    write!(stream, "\r\n")?;
    stream.flush()?;
    Ok(())
}

fn write_sse_event(stream: &mut TcpStream, event: &HubEvent) -> Result<()> {
    let data = serde_json::to_string(&event_view(event))
        .context("failed to serialise Morph Hub SSE event")?;
    write!(stream, "id: {}\nevent: morph-hub-event\n", event.id)?;
    for line in data.lines() {
        writeln!(stream, "data: {line}")?;
    }
    writeln!(stream)?;
    stream.flush()?;
    Ok(())
}

fn parse_last_event_id(request: &HttpRequest) -> Result<Option<u64>> {
    let Some(value) = request.header("last-event-id") else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .context("Last-Event-ID must be an unsigned integer")
}

fn try_acquire_counter(counter: Arc<AtomicUsize>, limit: usize) -> Option<CounterPermit> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(CounterPermit { counter }),
            Err(actual) => current = actual,
        }
    }
}

fn request_auth_scope(method: &str, path: &str) -> AuthScope {
    match (method, path) {
        ("GET", "/api/state-file")
        | ("POST", "/api/state-file/preview")
        | ("PUT", "/api/state-file") => AuthScope::Restore,
        ("POST", "/api/invoices") => AuthScope::Sign,
        ("POST", _) | ("PUT", _) => AuthScope::Write,
        _ => AuthScope::Read,
    }
}

fn api_error_response(
    status: u16,
    reason: &'static str,
    code: impl Into<String>,
    error: impl Into<String>,
    request_id: &str,
) -> HttpResponse {
    json_response(
        status,
        reason,
        &ApiErrorBody {
            error: error.into(),
            code: code.into(),
            request_id: request_id.to_string(),
        },
    )
}

fn public_api_error_message(err: &anyhow::Error) -> String {
    let message = err.to_string();
    let lower = message.to_ascii_lowercase();
    let internal = lower.starts_with("failed to ")
        || lower.contains("os error")
        || lower.contains("permission denied")
        || lower.contains("no such file")
        || lower.contains("lock is poisoned")
        || lower.contains("sync directory")
        || lower.contains("canonicalise");
    if internal {
        "request could not be processed; check Morph Hub logs with the request id".to_string()
    } else {
        message
    }
}

fn with_header(
    mut response: HttpResponse,
    name: &'static str,
    value: impl Into<String>,
) -> HttpResponse {
    response.headers.push((name, value.into()));
    response
}

fn json_response<T: Serialize>(status: u16, reason: &'static str, value: &T) -> HttpResponse {
    HttpResponse {
        status,
        reason,
        content_type: "application/json; charset=utf-8",
        headers: Vec::new(),
        body: serde_json::to_vec_pretty(value)
            .unwrap_or_else(|_| b"{\"error\":\"failed to serialise response\"}".to_vec()),
    }
}

fn empty_response(status: u16, reason: &'static str) -> HttpResponse {
    HttpResponse {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn static_path(ui_dir: &Path, request_path: &str) -> Result<PathBuf> {
    let clean = request_path.trim_start_matches('/');
    ensure!(
        !clean.contains('\0'),
        "static path must not contain NUL bytes"
    );
    ensure!(
        !clean
            .split('/')
            .any(|part| part == ".." || percent_decoded_component_is_parent(part)),
        "static path must not traverse directories"
    );
    let path = if clean.is_empty() {
        ui_dir.join("index.html")
    } else {
        ui_dir.join(clean)
    };
    if path.exists() {
        let root = ui_dir
            .canonicalize()
            .with_context(|| format!("failed to canonicalise UI directory {}", ui_dir.display()))?;
        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalise static asset {}", path.display()))?;
        ensure!(
            canonical.starts_with(&root),
            "static asset path resolves outside the UI directory"
        );
        return Ok(canonical);
    }
    Ok(path)
}

fn percent_decoded_component_is_parent(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let Some(high) = hex_value(bytes[index + 1]) else {
                decoded.push(bytes[index]);
                index += 1;
                continue;
            };
            let Some(low) = hex_value(bytes[index + 2]) else {
                decoded.push(bytes[index]);
                index += 1;
                continue;
            };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded == b".."
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn static_cache_headers(path: &Path) -> Vec<(&'static str, String)> {
    let cache_control = if path.file_name().and_then(|name| name.to_str()) == Some("index.html") {
        "no-cache, must-revalidate"
    } else if path
        .components()
        .any(|component| component.as_os_str() == "assets")
    {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    vec![("Cache-Control", cache_control.to_string())]
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn persisted_peer(
    peer: &MorphPeer,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedPeer> {
    Ok(PersistedPeer {
        pubkey: pubkey_for_node_id(&peer.node_id, peer_pubkeys)?.to_string(),
        alias: peer.alias.clone(),
    })
}

fn persisted_channel(
    channel: &MorphChannelRecord,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedChannel> {
    Ok(PersistedChannel {
        channel_id: hex_prefixed(&channel.channel_id),
        counterparty_pubkey: pubkey_for_node_id(&channel.counterparty_node_id, peer_pubkeys)?
            .to_string(),
        funding_epoch: channel.funding_epoch,
        funding_context_id: hex_prefixed(&channel.funding_context_id),
        state_number: channel.state_number,
        phase: channel.phase,
        balances: channel.balances.clone(),
        sponsor_budget: channel.sponsor_budget,
    })
}

fn persisted_factory(
    factory: &MorphFactoryRecord,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<PersistedFactory> {
    Ok(PersistedFactory {
        factory_id: hex_prefixed(&factory.factory_id),
        participant_pubkeys: participant_pubkeys(
            &factory.participant_node_ids,
            local_node_id,
            local_pubkey,
            peer_pubkeys,
        )?,
        update_number: factory.update_number,
        reserve_balances: factory.reserve_balances.clone(),
        materialised_child_channels: factory
            .materialised_child_channels
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
    })
}

fn peer_view(peer: &MorphPeer, peer_pubkeys: &BTreeMap<Bytes32, String>) -> Result<PeerView> {
    Ok(PeerView {
        pubkey: pubkey_for_node_id(&peer.node_id, peer_pubkeys)?.to_string(),
        node_id: hex_prefixed(&peer.node_id),
        alias: peer.alias.clone(),
        provenance: local_state_provenance(),
    })
}

fn channel_view(
    channel: &MorphChannelRecord,
    factory_id: Option<Bytes32>,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<ChannelView> {
    Ok(ChannelView {
        channel_id: hex_prefixed(&channel.channel_id),
        factory_id: factory_id.map(|id| hex_prefixed(&id)),
        counterparty_pubkey: pubkey_for_node_id(&channel.counterparty_node_id, peer_pubkeys)?
            .to_string(),
        counterparty_node_id: hex_prefixed(&channel.counterparty_node_id),
        funding_epoch: channel.funding_epoch,
        funding_context_id: hex_prefixed(&channel.funding_context_id),
        state_number: channel.state_number,
        phase: phase_label(channel.phase),
        balances: channel.balances.iter().map(balance_view).collect(),
        sponsor_budget: channel.sponsor_budget,
        provenance: local_state_provenance(),
    })
}

fn invoice_view(
    stored: &StoredMorphInvoice,
    _local_node_id: Bytes32,
    _local_pubkey: &str,
) -> InvoiceView {
    InvoiceView {
        invoice_id: hex_prefixed(&stored.invoice.invoice_id),
        encoded_invoice: stored.encoded_invoice.clone(),
        status: invoice_status_label(stored.status),
        network: network_label(stored.invoice.network),
        payee_pubkey: Some(hex::encode(&stored.invoice.payee_pubkey_sec1)),
        payee_node_id: hex_prefixed(&stored.invoice.payee_node_id),
        channel_id: stored.invoice.channel_id.map(|id| hex_prefixed(&id)),
        asset: asset_view(&stored.invoice.asset),
        amount: stored.invoice.amount.to_string(),
        created_at_unix: stored.invoice.created_at_unix,
        expires_at_unix: stored.invoice.expires_at_unix,
        payment_hash: hex_prefixed(&stored.invoice.payment_hash),
        description: stored.invoice.description.clone(),
        received_at_unix: stored.received_at_unix,
        paid_at_unix: stored.paid_at_unix,
        cancelled_at_unix: stored.cancelled_at_unix,
        provenance: local_state_provenance(),
    }
}

fn factory_view(
    factory: &MorphFactoryRecord,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<FactoryView> {
    Ok(FactoryView {
        factory_id: hex_prefixed(&factory.factory_id),
        participant_pubkeys: participant_pubkeys(
            &factory.participant_node_ids,
            local_node_id,
            local_pubkey,
            peer_pubkeys,
        )?,
        participant_node_ids: factory
            .participant_node_ids
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
        update_number: factory.update_number,
        reserve_balances: factory.reserve_balances.iter().map(balance_view).collect(),
        materialised_child_channels: factory
            .materialised_child_channels
            .iter()
            .map(|id| hex_prefixed(id))
            .collect(),
        provenance: local_state_provenance(),
    })
}

fn participant_pubkeys(
    participant_node_ids: &BTreeSet<Bytes32>,
    local_node_id: Bytes32,
    local_pubkey: &str,
    peer_pubkeys: &BTreeMap<Bytes32, String>,
) -> Result<Vec<String>> {
    participant_node_ids
        .iter()
        .map(|id| {
            if *id == local_node_id {
                Ok(local_pubkey.to_string())
            } else {
                Ok(pubkey_for_node_id(id, peer_pubkeys)?.to_string())
            }
        })
        .collect()
}

fn pubkey_for_node_id<'a>(
    node_id: &Bytes32,
    peer_pubkeys: &'a BTreeMap<Bytes32, String>,
) -> Result<&'a str> {
    peer_pubkeys
        .get(node_id)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing pubkey for node id {}", hex_prefixed(node_id)))
}

fn balance_view(balance: &MorphAssetBalance) -> BalanceView {
    BalanceView {
        asset: asset_view(&balance.asset),
        local: balance.local.to_string(),
        remote: balance.remote.to_string(),
        pending: balance.pending.to_string(),
    }
}

fn event_view(event: &HubEvent) -> EventView {
    EventView {
        id: event.id,
        severity: event.severity,
        event: event.event.clone(),
        subject_id: event.subject_id.map(|id| hex_prefixed(&id)),
        message: event.message.clone(),
        created_at_unix: event.created_at_unix,
        provenance: local_state_provenance(),
    }
}

fn load_watchtower_alerts(path: &Path) -> (bool, Vec<WatchtowerAlertView>, Option<String>) {
    if !path.exists() {
        return (false, Vec::new(), None);
    }

    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            return (
                true,
                Vec::new(),
                Some(format!(
                    "failed to open watchtower alert file {}: {err}",
                    path.display()
                )),
            );
        }
    };
    let reader = BufReader::new(file);
    let mut alerts = Vec::new();
    let mut last_error = None;

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                last_error.get_or_insert_with(|| {
                    format!(
                        "failed to read watchtower alert file {} line {line_number}: {err}",
                        path.display()
                    )
                });
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<WatchtowerAlert>(&line) {
            Ok(alert) if alert.schema == WATCHTOWER_ALERT_SCHEMA => {
                alerts.push(watchtower_alert_view(alert));
            }
            Ok(alert) => {
                last_error.get_or_insert_with(|| {
                    format!(
                        "watchtower alert file {} line {line_number} has unsupported schema {}",
                        path.display(),
                        alert.schema
                    )
                });
            }
            Err(err) => {
                last_error.get_or_insert_with(|| {
                    format!(
                        "watchtower alert file {} line {line_number} is not valid JSON: {err}",
                        path.display()
                    )
                });
            }
        }
    }

    if alerts.len() > MAX_WATCHTOWER_ALERTS {
        alerts = alerts.split_off(alerts.len() - MAX_WATCHTOWER_ALERTS);
    }
    alerts.reverse();
    (true, alerts, last_error)
}

fn watchtower_alert_view(alert: WatchtowerAlert) -> WatchtowerAlertView {
    WatchtowerAlertView {
        schema: alert.schema,
        created_unix_ms: alert.created_unix_ms,
        channel_id: alert.channel_id,
        severity: alert.severity,
        event: alert.event,
        message: alert.message,
        selected_state_number: alert.selected_state_number,
        observed_state_number: alert.observed_state_number,
        observed_out_point: alert.observed_out_point,
        publication_tx_hash: alert.publication_tx_hash,
        selected_funding_anchor: alert.selected_funding_anchor,
        observed_funding_anchor: alert.observed_funding_anchor,
        selected_funding_context_id: alert.selected_funding_context_id,
        observed_funding_context_id: alert.observed_funding_context_id,
        scanned_to_block: alert.scanned_to_block,
        next_from_block: alert.next_from_block,
        provenance: watchtower_alert_provenance(),
    }
}

fn asset_view(asset: &MorphAsset) -> AssetView {
    match asset {
        MorphAsset::Ckb => AssetView::Ckb,
        MorphAsset::Xudt(type_hash) => AssetView::Xudt {
            type_hash: hex_prefixed(type_hash),
        },
    }
}

fn network_label(network: MorphNetwork) -> &'static str {
    match network {
        MorphNetwork::Devnet => "devnet",
        MorphNetwork::Testnet => "testnet",
        MorphNetwork::Mainnet => "mainnet",
    }
}

fn phase_label(phase: Phase) -> &'static str {
    match phase {
        Phase::Funding => "funding",
        Phase::Active => "active",
        Phase::Settling => "settling",
        Phase::Closed => "closed",
    }
}

fn invoice_status_label(status: MorphInvoiceStatus) -> &'static str {
    match status {
        MorphInvoiceStatus::Open => "open",
        MorphInvoiceStatus::Received => "received",
        MorphInvoiceStatus::Paid => "paid",
        MorphInvoiceStatus::Cancelled => "cancelled",
        MorphInvoiceStatus::Expired => "expired",
    }
}

fn flow_label(flow: MorphBusinessFlow) -> &'static str {
    match flow {
        MorphBusinessFlow::PeerConnected => "peer",
        MorphBusinessFlow::InvoiceCreated => "invoice-created",
        MorphBusinessFlow::InvoiceReceived => "invoice-received",
        MorphBusinessFlow::InvoiceSettled => "invoice-settled",
        MorphBusinessFlow::ChannelOpened => "channel-opened",
        MorphBusinessFlow::StatePublished => "state-published",
        MorphBusinessFlow::ChannelFinalised => "channel-finalised",
        MorphBusinessFlow::ChannelSpliced => "channel-spliced",
        MorphBusinessFlow::FactoryOpened => "factory-opened",
        MorphBusinessFlow::FactoryAdvanced => "factory-advanced",
        MorphBusinessFlow::FactoryChildMaterialised => "factory-child",
    }
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditional_packages::fixture_package as conditional_fixture_package;
    use crate::watch_alert::append_watchtower_alert;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    static TEST_STATE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn persisted_state_requires_current_collections_and_rejects_unknown_fields() {
        let server = test_server(&pubkey_from_scalar(41));
        let store = server.store.lock().unwrap();
        let current = serde_json::to_value(store.persisted().unwrap()).unwrap();
        for field in [
            "conditional_batches",
            "multi_asset_packages",
            "root_fundings",
        ] {
            let mut incomplete = current.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<PersistedHubState>(incomplete).is_err());
        }
        let mut unknown = current;
        unknown["obsolete_field"] = json!([]);
        assert!(serde_json::from_value::<PersistedHubState>(unknown).is_err());
    }

    #[test]
    fn conditional_force_package_is_validated_linked_and_persisted() {
        let local_pubkey = pubkey_from_scalar(41);
        let peer_pubkey = pubkey_from_scalar(42);
        let server = test_server(&local_pubkey);
        let package = conditional_fixture_package().unwrap();

        let opened = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": package.channel_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "conditional-peer",
                "funding_context_id": package.funding_context_id,
                "local": "12000000000",
                "remote": "8000000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(opened.status, 200);
        let published = route_json(
            &server,
            "POST",
            format!("/api/channels/{}/publish", package.channel_id),
            json!({
                "funding_context_id": package.funding_context_id,
                "state_number": package.state_number
            }),
        );
        assert_eq!(published.status, 200);

        let imported = route_json(
            &server,
            "POST",
            "/api/conditional-batches",
            serde_json::to_value(&package).unwrap(),
        );
        assert_eq!(imported.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&imported.body).unwrap();
        assert_eq!(body["conditional_batches"].as_array().unwrap().len(), 1);

        let (path, persisted_pubkey) = {
            let store = server.store.lock().unwrap();
            (store.path.clone(), store.state.pubkey.clone())
        };
        let reloaded =
            HubStore::load_or_create(path, &persisted_pubkey, MorphNetwork::Devnet).unwrap();
        assert_eq!(reloaded.state.conditional_batches.len(), 1);
    }

    #[test]
    fn root_funding_coordination_retains_exit_before_creation_and_survives_restart() {
        let fixture = crate::multi_asset_funding::root_collection_tests::fixture();
        let draft: RootFundingDraft = serde_json::from_value(fixture["draft"].clone()).unwrap();
        let id = fixture["inspection"]["transaction_hash"].as_str().unwrap();
        let local = draft.participants[0].trim_start_matches("0x");
        let peer = draft.participants[1].trim_start_matches("0x");
        let server = test_server(local);
        let absent_peer = route_json(
            &server,
            "POST",
            "/api/root-fundings",
            fixture["draft"].clone(),
        );
        assert_ne!(absent_peer.status, 200);
        assert_eq!(
            route_json(
                &server,
                "POST",
                "/api/peers",
                json!({"pubkey":peer,"alias":"funding-peer"})
            )
            .status,
            200
        );
        assert_eq!(
            route_json(
                &server,
                "POST",
                "/api/root-fundings",
                fixture["draft"].clone()
            )
            .status,
            200
        );
        let (path, pubkey) = {
            let store = server.store.lock().unwrap();
            (store.path.clone(), store.state.pubkey.clone())
        };
        let before = fs::read(&path).unwrap();
        let receipt_path = format!("/api/root-fundings/{id}/signatures");
        let export_path = format!("/api/root-fundings/{id}/export");
        assert_ne!(
            route_json(
                &server,
                "POST",
                &receipt_path,
                json!({"target":"creation","receipt":fixture["creation_receipts"][0]})
            )
            .status,
            200
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_ne!(
            route_json(&server, "GET", &export_path, json!({})).status,
            200
        );
        for receipt in fixture["exit_receipts"].as_array().unwrap() {
            assert_eq!(
                route_json(
                    &server,
                    "POST",
                    &receipt_path,
                    json!({"target":"exit","receipt":receipt})
                )
                .status,
                200
            );
        }
        // A failed durable write cannot publish a receipt or mutate in-memory coordination.
        let blocker = path.with_extension("blocker");
        fs::write(&blocker, "not a directory").unwrap();
        server.store.lock().unwrap().path = blocker.join("state.json");
        assert_ne!(
            route_json(
                &server,
                "POST",
                &receipt_path,
                json!({"target":"creation","receipt":fixture["creation_receipts"][0]})
            )
            .status,
            200
        );
        assert_eq!(
            server
                .store
                .lock()
                .unwrap()
                .state
                .root_fundings
                .values()
                .next()
                .unwrap()
                .collection
                .creation_signatures
                .len(),
            0
        );
        server.store.lock().unwrap().path = path.clone();
        for receipt in fixture["creation_receipts"].as_array().unwrap() {
            assert_eq!(
                route_json(
                    &server,
                    "POST",
                    &receipt_path,
                    json!({"target":"creation","receipt":receipt})
                )
                .status,
                200
            );
        }
        let exported = route_json(&server, "GET", &export_path, json!({}));
        assert_eq!(exported.status, 200);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&exported.body).unwrap(),
            fixture["funding"]
        );
        let persisted = fs::read(&path).unwrap();
        assert_eq!(
            route_json(
                &server,
                "POST",
                &receipt_path,
                json!({"target":"creation","receipt":fixture["creation_receipts"][0]})
            )
            .status,
            200
        );
        assert_eq!(fs::read(&path).unwrap(), persisted);
        let reloaded = HubStore::load_or_create(path, &pubkey, MorphNetwork::Devnet).unwrap();
        assert_eq!(reloaded.state.root_fundings.len(), 1);
        assert!(
            reloaded
                .state
                .root_fundings
                .values()
                .next()
                .unwrap()
                .summary
                .ready_to_export
        );
        assert!(
            reloaded.state.node.channels.is_empty(),
            "a proposal must never masquerade as a funded operating channel"
        );
    }

    #[test]
    fn multi_asset_recovery_is_bound_to_participants_and_survives_restart() {
        let package = crate::multi_asset_packages::fixture_package().unwrap();
        let summary = package.validate().unwrap();
        let local = summary.signer_pubkeys[0].trim_start_matches("0x");
        let peer = summary.signer_pubkeys[1].trim_start_matches("0x");
        let server = test_server(local);
        let opened = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": summary.channel_id, "counterparty_pubkey": peer, "counterparty_alias": "multi-asset-peer",
                "funding_context_id": summary.funding_context_id, "local": "500", "remote": "500", "sponsor_budget": 1000000,
                "asset": { "kind": "xudt", "type_hash": summary.assets[0].type_hash }
            }),
        );
        assert_eq!(opened.status, 200);
        let published = route_json(
            &server,
            "POST",
            format!("/api/channels/{}/publish", summary.channel_id),
            json!({
                "funding_context_id": summary.funding_context_id, "state_number": summary.state_number.parse::<u64>().unwrap()
            }),
        );
        assert_eq!(published.status, 200);
        let imported = route_json(
            &server,
            "POST",
            "/api/multi-asset-packages",
            serde_json::to_value(&package).unwrap(),
        );
        assert_eq!(
            imported.status,
            200,
            "{}",
            String::from_utf8_lossy(&imported.body)
        );
        let view: serde_json::Value = serde_json::from_slice(&imported.body).unwrap();
        assert_eq!(view["multi_asset_package_count"], 1);
        assert_eq!(
            view["multi_asset_packages"][0]["package_id"],
            summary.package_id
        );
        assert!(view["multi_asset_packages"][0].get("witness_hex").is_none());
        let exported = route_empty(
            &server,
            "GET",
            format!("/api/multi-asset-packages/{}", summary.package_id),
        );
        assert_eq!(exported.status, 200);
        assert_eq!(
            serde_json::from_slice::<StoredMultiAssetPackage>(&exported.body).unwrap(),
            package
        );
        let duplicate = route_json(
            &server,
            "POST",
            "/api/multi-asset-packages",
            serde_json::to_value(&package).unwrap(),
        );
        assert_eq!(duplicate.status, 200);
        let (path, pubkey) = {
            let store = server.store.lock().unwrap();
            (store.path.clone(), store.state.pubkey.clone())
        };
        let reloaded = HubStore::load_or_create(path, &pubkey, MorphNetwork::Devnet).unwrap();
        assert_eq!(reloaded.state.multi_asset_packages.len(), 1);
        let retained = reloaded.state.multi_asset_packages.values().next().unwrap();
        assert_eq!(retained.package, package);
        assert_eq!(retained.summary, summary);
        let advanced = route_json(
            &server,
            "POST",
            format!("/api/channels/{}/publish", summary.channel_id),
            json!({
                "funding_context_id": summary.funding_context_id, "state_number": 10
            }),
        );
        assert_eq!(advanced.status, 200);
        let stale = route_json(
            &server,
            "POST",
            "/api/multi-asset-packages",
            serde_json::to_value(&package).unwrap(),
        );
        assert_eq!(stale.status, 400);
        assert_eq!(
            server
                .store
                .lock()
                .unwrap()
                .state
                .multi_asset_packages
                .len(),
            1
        );
    }

    #[test]
    fn multi_asset_recovery_rejects_foreign_participants_and_malformed_restore() {
        let package = crate::multi_asset_packages::fixture_package().unwrap();
        let summary = package.validate().unwrap();
        let server = test_server(&pubkey_from_scalar(41));
        let opened = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": summary.channel_id, "counterparty_pubkey": pubkey_from_scalar(42), "counterparty_alias": "foreign-peer",
                "funding_context_id": summary.funding_context_id, "local": "500", "remote": "500", "sponsor_budget": 1000000,
                "asset": { "kind": "xudt", "type_hash": summary.assets[0].type_hash }
            }),
        );
        assert_eq!(opened.status, 200);
        let published = route_json(
            &server,
            "POST",
            format!("/api/channels/{}/publish", summary.channel_id),
            json!({
                "funding_context_id": summary.funding_context_id, "state_number": 9
            }),
        );
        assert_eq!(published.status, 200);
        let imported = route_json(
            &server,
            "POST",
            "/api/multi-asset-packages",
            serde_json::to_value(&package).unwrap(),
        );
        assert_eq!(imported.status, 400);
        assert!(String::from_utf8_lossy(&imported.body).contains("signers do not match"));
        let store = server.store.lock().unwrap();
        let mut persisted = store.persisted().unwrap();
        let mut malformed = package;
        malformed.witness_hex.push_str("00");
        persisted.multi_asset_packages.push(malformed);
        assert!(HubRuntimeState::from_persisted(persisted).is_err());
    }

    #[test]
    fn multi_asset_recovery_alone_is_operational_restore_state() {
        let server = test_server(&pubkey_from_scalar(41));
        let store = server.store.lock().unwrap();
        let mut persisted = store.persisted().unwrap();
        persisted
            .multi_asset_packages
            .push(crate::multi_asset_packages::fixture_package().unwrap());
        let preview = store.restore_preview(persisted).unwrap();
        assert!(!preview.allowed);
        assert_eq!(preview.candidate.multi_asset_packages, 1);
    }

    #[test]
    fn request_parser_rejects_oversized_request_lines() {
        let valid = b"GET /api/state HTTP/1.1\r\nHost: morph.local\r\n\r\n";
        let request = read_request_from_reader(Cursor::new(valid)).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/state");

        let oversized = format!(
            "GET /{} HTTP/1.1\r\nHost: morph.local\r\n\r\n",
            "a".repeat(MAX_REQUEST_LINE_BYTES)
        );
        let err = read_request_from_reader(Cursor::new(oversized.into_bytes()))
            .expect_err("oversized HTTP request line should be rejected");
        assert!(
            err.to_string().contains("HTTP line exceeds"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_parser_rejects_duplicate_content_length() {
        let duplicate =
            b"POST /api/peers HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        let err = read_request_from_reader(Cursor::new(duplicate))
            .expect_err("duplicate Content-Length should be rejected");
        assert!(
            err.to_string().contains("duplicate Content-Length"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_parser_rejects_duplicate_authorization() {
        let duplicate = b"GET /api/state HTTP/1.1\r\nAuthorization: Bearer first\r\nauthorization: Bearer second\r\n\r\n";
        let err = read_request_from_reader(Cursor::new(duplicate))
            .expect_err("duplicate Authorization should be rejected");
        assert!(
            err.to_string().contains("duplicate Authorization header"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_head_can_be_authenticated_before_body_is_read() {
        let headers = b"POST /api/peers HTTP/1.1\r\nContent-Length: 1024\r\n\r\n";
        let mut reader = RequestReader::without_deadline(Cursor::new(headers));
        let (request, content_length) = read_request_head_from_reader(&mut reader).unwrap();
        assert_eq!(request.path, "/api/peers");
        assert_eq!(content_length, 1024);
        assert!(request.body.is_empty());
    }

    #[test]
    fn request_reader_rejects_an_expired_total_deadline() {
        let valid = b"GET /api/state HTTP/1.1\r\nHost: morph.local\r\n\r\n";
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let mut reader = RequestReader::with_deadline(Cursor::new(valid), expired, None);
        let err = read_request_head_from_reader(&mut reader)
            .expect_err("an expired request deadline should fail before parsing");
        assert!(
            err.to_string().contains("total read deadline"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_reader_enforces_total_deadline_across_partial_reads() {
        struct SlowOneByteReader {
            bytes: &'static [u8],
            offset: usize,
        }

        impl Read for SlowOneByteReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.offset == self.bytes.len() || buf.is_empty() {
                    return Ok(0);
                }
                thread::sleep(Duration::from_millis(20));
                buf[0] = self.bytes[self.offset];
                self.offset += 1;
                Ok(1)
            }
        }

        let deadline = Instant::now()
            .checked_add(Duration::from_millis(5))
            .unwrap();
        let slow = SlowOneByteReader {
            bytes: b"GET /api/state HTTP/1.1\r\n\r\n",
            offset: 0,
        };
        let mut reader = RequestReader::with_deadline(slow, deadline, None);
        let err = read_request_head_from_reader(&mut reader)
            .expect_err("partial reads must not reset the total request deadline");
        assert!(
            err.to_string().contains("total read deadline"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn request_parser_rejects_unsupported_transfer_encoding_and_version() {
        let chunked = b"POST /api/peers HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let err = read_request_from_reader(Cursor::new(chunked))
            .expect_err("chunked request should be rejected");
        assert!(
            err.to_string().contains("Transfer-Encoding"),
            "unexpected error: {err:#}"
        );

        let http2 = b"GET /api/state HTTP/2.0\r\nHost: morph.local\r\n\r\n";
        let err =
            read_request_from_reader(Cursor::new(http2)).expect_err("HTTP/2.0 should be rejected");
        assert!(
            err.to_string().contains("HTTP request version"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn static_path_rejects_symlink_escape() {
        let ui_dir = temp_file_path("ui-root", "dir");
        fs::create_dir_all(&ui_dir).unwrap();
        let outside = temp_file_path("outside-ui", "txt");
        fs::write(&outside, b"private").unwrap();
        symlink(&outside, ui_dir.join("leak.txt")).unwrap();

        let err = static_path(&ui_dir, "/leak.txt")
            .expect_err("static symlink escaping UI root should be rejected");
        assert!(
            err.to_string().contains("outside the UI directory"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn static_path_rejects_percent_decoded_parent_dir() {
        let ui_dir = temp_file_path("ui-root-percent", "dir");
        fs::create_dir_all(&ui_dir).unwrap();

        let err = static_path(&ui_dir, "/%2e%2e/secrets.txt")
            .expect_err("percent-decoded parent traversal should be rejected");
        assert!(
            err.to_string().contains("traverse directories"),
            "unexpected error: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hub_state_file_is_owner_only_and_redacts_invoice_preimage() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let path = server.store.lock().unwrap().path.clone();
        assert_eq!(state_file_mode(&path), 0o600);

        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "private invoice",
                "payment_preimage": bytes32_hex(51),
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        assert_eq!(state_file_mode(&path), 0o600);

        let persisted = fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("payment_preimage"));
        assert!(!persisted.contains(&bytes32_hex(51)));

        let state_file = route_empty(&server, "GET", "/api/state-file");
        let exported = String::from_utf8(state_file.body).unwrap();
        assert!(!exported.contains("payment_preimage"));
        assert!(!exported.contains(&bytes32_hex(51)));
    }

    #[test]
    fn rejected_mutation_does_not_commit_partial_peer_state() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_one_pubkey = pubkey_from_scalar(2);
        let peer_two_pubkey = pubkey_from_scalar(3);
        let server = test_server(&local_pubkey);

        let factory_id = hex_repeat('5');
        let child_id = hex_repeat('6');
        let funding_context_id = hex_repeat('7');
        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_one_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_two_pubkey.as_str(),
                "counterparty_alias": "not-member",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 400);

        let state = route_empty(&server, "GET", "/api/state");
        assert_eq!(state.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        let peers = body["peers"].as_array().unwrap();
        assert!(
            peers
                .iter()
                .all(|peer| peer["pubkey"].as_str() != Some(peer_two_pubkey.as_str())),
            "failed materialise-child request leaked non-participant peer into hub state"
        );

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_one_pubkey.as_str(),
                "counterparty_alias": "member",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["pubkey"].as_str() == Some(peer_one_pubkey.as_str()))
        );
        assert!(
            body["channels"]
                .as_array()
                .unwrap()
                .iter()
                .any(|channel| channel["channel_id"].as_str() == Some(child_id.as_str()))
        );
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("factory-child"))
        );
    }

    #[test]
    fn state_restore_is_disabled_by_default() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let state = route_empty(&server, "GET", "/api/state");
        let persisted: serde_json::Value = serde_json::from_slice(&state.body).unwrap();

        let response = route_restore_state_file(&server, persisted);

        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("--allow-state-restore")
        );
    }

    #[test]
    fn state_restore_creates_private_backup_before_commit() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let path = server.store.lock().unwrap().path.clone();
        let original = fs::read(&path).unwrap();
        let state_file = route_empty(&server, "GET", "/api/state-file");
        let persisted: serde_json::Value = serde_json::from_slice(&state_file.body).unwrap();

        let response = route_restore_state_file(&server, persisted);

        assert_eq!(response.status, 200);
        let backup_paths = state_backup_paths(&path);
        assert_eq!(backup_paths.len(), 1, "expected one backup for {path:?}");
        assert_eq!(fs::read(&backup_paths[0]).unwrap(), original);
        #[cfg(unix)]
        assert_eq!(state_file_mode(&backup_paths[0]), 0o600);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let event = &body["events"].as_array().unwrap()[0];
        assert_eq!(event["event"].as_str(), Some("state_restored"));
        assert_eq!(event["severity"].as_str(), Some("critical"));
        assert!(
            event["message"]
                .as_str()
                .unwrap()
                .contains("previous state was backed up")
        );
    }

    #[test]
    fn state_restore_requires_current_confirmation_hash() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let state_file = route_empty(&server, "GET", "/api/state-file");
        let persisted: serde_json::Value = serde_json::from_slice(&state_file.body).unwrap();

        let response = route_json(
            &server,
            "PUT",
            "/api/state-file",
            json!({
                "state": persisted,
                "confirmation_hash": bytes32_hex(94)
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("confirmation_hash")
        );
    }

    #[test]
    fn state_restore_cannot_inject_completed_flows() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let state_file = route_empty(&server, "GET", "/api/state-file");
        let mut persisted: serde_json::Value = serde_json::from_slice(&state_file.body).unwrap();
        persisted["completed_flows"] =
            json!([serde_json::to_value(MorphBusinessFlow::PeerConnected).unwrap()]);

        let response = route_restore_state_file(&server, persisted);

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("empty bootstrap state")
        );

        let state_file = route_empty(&server, "GET", "/api/state-file");
        let persisted: serde_json::Value = serde_json::from_slice(&state_file.body).unwrap();
        assert_eq!(persisted["completed_flows"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn state_restore_rejects_replacing_operational_state() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let response = route_json(
            &server,
            "POST",
            "/api/peers",
            json!({ "pubkey": peer_pubkey, "alias": "peer" }),
        );
        assert_eq!(response.status, 200);
        let state_file = route_empty(&server, "GET", "/api/state-file");
        let mut persisted: serde_json::Value = serde_json::from_slice(&state_file.body).unwrap();
        persisted["peers"] = json!([]);
        persisted["completed_flows"] = json!([]);

        let response = route_json(
            &server,
            "PUT",
            "/api/state-file",
            json!({
                "state": persisted,
                "confirmation_hash": bytes32_hex(91)
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("empty bootstrap state")
        );
    }

    #[test]
    fn existing_state_file_must_match_requested_network() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let path = server.store.lock().unwrap().path.clone();

        let err = match HubStore::load_or_create(path, &local_pubkey, MorphNetwork::Testnet) {
            Ok(_) => panic!("network-mismatched hub state file was accepted"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("hub state network devnet"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn state_restore_rejects_pubkey_mismatch_without_commit() {
        let local_pubkey = pubkey_from_scalar(1);
        let other_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let response = route_empty(&server, "GET", "/api/state-file");
        assert_eq!(response.status, 200);
        let mut persisted: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        persisted["pubkey"] = json!(other_pubkey);

        let response = route_json(
            &server,
            "PUT",
            "/api/state-file",
            json!({
                "state": persisted,
                "confirmation_hash": bytes32_hex(92)
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("does not match running pubkey")
        );
        let state = route_empty(&server, "GET", "/api/state");
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        assert_eq!(body["pubkey"].as_str(), Some(local_pubkey.as_str()));
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn state_restore_rejects_network_mismatch_without_commit() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, None, true, None);
        let response = route_empty(&server, "GET", "/api/state-file");
        assert_eq!(response.status, 200);
        let mut persisted: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        persisted["network"] = serde_json::to_value(MorphNetwork::Testnet).unwrap();

        let response = route_json(
            &server,
            "PUT",
            "/api/state-file",
            json!({
                "state": persisted,
                "confirmation_hash": bytes32_hex(93)
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("does not match running network")
        );
        let state = route_empty(&server, "GET", "/api/state");
        let body: serde_json::Value = serde_json::from_slice(&state.body).unwrap();
        assert_eq!(body["network"].as_str(), Some("devnet"));
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn auth_token_protects_api_routes() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server_with_options(&local_pubkey, Some("secret-token"), false, None);

        let response = route_empty(&server, "GET", "/api/state");
        assert_eq!(response.status, 401);
        assert!(response_header(&response, "X-Morph-Hub-Request-Id").is_some());

        let response = route_empty_with_headers(
            &server,
            "GET",
            "/api/state",
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["security"]["auth_required"].as_bool(), Some(true));
        assert_eq!(body["security"]["single_operator"].as_bool(), Some(true));
    }

    #[test]
    fn auth_tokens_are_hashed_before_fixed_size_comparison() {
        let token = parse_hub_auth_token(Some("read,write:secret-token".to_string()))
            .unwrap()
            .unwrap();
        let matching = blake2b256(b"secret-token");
        let shorter = blake2b256(b"secret-toke");
        let longer = blake2b256(b"secret-token-longer");

        assert_eq!(token.secret_hash, matching);
        assert!(token.scopes.contains(&AuthScope::Read));
        assert!(token.scopes.contains(&AuthScope::Write));
        assert!(constant_time_eq(&matching, &token.secret_hash));
        assert!(!constant_time_eq(&shorter, &token.secret_hash));
        assert!(!constant_time_eq(&longer, &token.secret_hash));
    }

    #[test]
    fn api_auth_is_required_without_explicit_loopback_escape() {
        let local_pubkey = pubkey_from_scalar(1);
        let mut server = test_server(&local_pubkey);
        server.allow_unauthenticated_loopback = false;

        let response = route_empty(&server, "GET", "/api/state");

        assert_eq!(response.status, 401);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"].as_str(), Some("auth_required"));
    }

    #[test]
    fn scoped_auth_token_limits_write_and_restore_routes() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, Some("read:secret-token"), true, None);

        let response = route_empty_with_headers(
            &server,
            "GET",
            "/api/state",
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);

        let response = route_empty_with_headers(
            &server,
            "GET",
            "/api/state-file",
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["error"].as_str().unwrap().contains("restore scope"));

        let response = route_json_with_headers(
            &server,
            "POST",
            "/api/peers",
            json!({ "pubkey": peer_pubkey, "alias": "blocked" }),
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["error"].as_str().unwrap().contains("write scope"));
    }

    #[test]
    fn mutating_api_requests_are_rate_limited() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        server.rate_limiter.lock().unwrap().mutating_requests = MAX_MUTATIONS_PER_WINDOW;

        let response = route_json(
            &server,
            "POST",
            "/api/peers",
            json!({ "pubkey": peer_pubkey, "alias": "rate-limited" }),
        );

        assert_eq!(response.status, 429);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"].as_str(), Some("rate_limited"));
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("retry-after")
                && value.parse::<u64>().is_ok_and(|seconds| seconds >= 1)
        }));
    }

    #[test]
    fn mutation_concurrency_limit_rejects_excess_requests() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        server
            .active_mutations
            .store(MAX_CONCURRENT_MUTATIONS, Ordering::Relaxed);

        let response = route_json(
            &server,
            "POST",
            "/api/peers",
            json!({ "pubkey": peer_pubkey, "alias": "busy" }),
        );

        assert_eq!(response.status, 429);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"].as_str(), Some("too_many_mutations"));
    }

    #[test]
    fn static_responses_set_cache_control_headers() {
        let local_pubkey = pubkey_from_scalar(1);
        let mut server = test_server(&local_pubkey);
        let ui_dir = temp_file_path("ui-cache", "dir");
        let assets_dir = ui_dir.join("assets");
        fs::create_dir_all(&assets_dir).unwrap();
        fs::write(ui_dir.join("index.html"), b"<!doctype html>").unwrap();
        fs::write(assets_dir.join("index-abc123.js"), b"console.log('ok');").unwrap();
        server.ui_dir = ui_dir;

        let index = route_empty(&server, "GET", "/");
        assert_eq!(index.status, 200);
        assert_eq!(
            response_header(&index, "Cache-Control"),
            Some("no-cache, must-revalidate")
        );

        let asset = route_empty(&server, "GET", "/assets/index-abc123.js");
        assert_eq!(asset.status, 200);
        assert_eq!(
            response_header(&asset, "Cache-Control"),
            Some("public, max-age=31536000, immutable")
        );
    }

    #[test]
    fn event_stream_uses_api_auth_and_cursor_ordering() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server_with_options(&local_pubkey, Some("secret-token"), false, None);
        let unauthorised = request_empty("GET", "/api/events", std::iter::empty::<(&str, &str)>());
        assert!(
            server
                .auth_failure_response(&unauthorised, AuthScope::Read, "test")
                .is_some()
        );

        let authorised = request_empty(
            "GET",
            "/api/events",
            [("authorization", "Bearer secret-token")],
        );
        assert!(
            server
                .auth_failure_response(&authorised, AuthScope::Read, "test")
                .is_none()
        );
        assert_eq!(parse_last_event_id(&authorised).unwrap(), None);

        let response = route_json_with_headers(
            &server,
            "POST",
            "/api/peers",
            json!({
                "pubkey": peer_pubkey,
                "alias": "stream-peer"
            }),
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);
        let response = route_json_with_headers(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "stream invoice",
                "payment_preimage": bytes32_hex(41),
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
            [("authorization", "Bearer secret-token")],
        );
        assert_eq!(response.status, 200);

        let events = server.events_after(0);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, 1);
        assert_eq!(events[0].event, "peer_connected");
        assert_eq!(events[1].id, 2);
        assert_eq!(events[1].event, "invoice_created");
        assert_eq!(server.events_after(1).len(), 1);

        let resumed = request_empty("GET", "/api/events", [("last-event-id", "1")]);
        assert_eq!(parse_last_event_id(&resumed).unwrap(), Some(1));
    }

    #[test]
    fn state_exposes_watchtower_alert_file_evidence() {
        let local_pubkey = pubkey_from_scalar(1);
        let alert_path = temp_file_path("watch-alerts", "jsonl");
        let channel_id = bytes32_hex(71);
        let publication_tx_hash = bytes32_hex(72);
        let alert = WatchtowerAlert::new(
            channel_id.clone(),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::PublicationSubmitted,
            "published saved state 2 against older StateCell 0".to_string(),
            2,
            884,
            885,
        )
        .unwrap()
        .with_observed(0, format!("{}:0", bytes32_hex(73)))
        .with_publication(publication_tx_hash.clone())
        .with_funding_anchors(bytes32_hex(74), bytes32_hex(74))
        .with_optional_funding_contexts(Some(bytes32_hex(75)), Some(bytes32_hex(75)));
        append_watchtower_alert(&alert_path, &alert).unwrap();
        let server = test_server_with_watch_alert_file(&local_pubkey, alert_path.clone());

        let response = route_empty(&server, "GET", "/api/state");

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["watchtower"]["configured"].as_bool(), Some(true));
        assert_eq!(body["watchtower"]["file_exists"].as_bool(), Some(true));
        let expected_alert_file = alert_path.display().to_string();
        assert_eq!(
            body["watchtower"]["alert_file"].as_str(),
            Some(expected_alert_file.as_str())
        );
        assert_eq!(body["watchtower"]["last_error"].as_str(), None);
        let alert = &body["watchtower"]["alerts"][0];
        assert_eq!(alert["channel_id"].as_str(), Some(channel_id.as_str()));
        assert_eq!(alert["event"].as_str(), Some("publication_submitted"));
        assert_eq!(
            alert["publication_tx_hash"].as_str(),
            Some(publication_tx_hash.as_str())
        );
        assert_eq!(
            alert["provenance"]["source"].as_str(),
            Some("watchtower_alert_file")
        );
        assert_eq!(
            alert["provenance"]["chain_status"].as_str(),
            Some("watchtower_alert")
        );
    }

    #[test]
    fn malformed_watchtower_alert_file_does_not_break_state_response() {
        let local_pubkey = pubkey_from_scalar(1);
        let alert_path = temp_file_path("bad-watch-alerts", "jsonl");
        fs::write(&alert_path, b"{not-json}\n").unwrap();
        let server = test_server_with_watch_alert_file(&local_pubkey, alert_path);

        let response = route_empty(&server, "GET", "/api/state");

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["watchtower"]["configured"].as_bool(), Some(true));
        assert_eq!(body["watchtower"]["file_exists"].as_bool(), Some(true));
        assert_eq!(body["watchtower"]["alerts"].as_array().unwrap().len(), 0);
        assert!(
            body["watchtower"]["last_error"]
                .as_str()
                .unwrap()
                .contains("line 1")
        );
    }

    #[test]
    fn invoice_api_flow_creates_receives_and_settles() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let preimage = bytes32_hex(11);

        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "integration invoice",
                "payment_preimage": preimage,
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let invoice_id = body["invoices"][0]["invoice_id"].as_str().unwrap();
        assert_eq!(
            body["invoices"][0]["provenance"]["chain_status"].as_str(),
            Some("not_chain_verified")
        );
        assert_eq!(
            body["invoices"][0]["provenance"]["label"].as_str(),
            Some("Local only")
        );
        assert!(
            body["invoices"][0]["provenance"]["message"]
                .as_str()
                .unwrap()
                .contains("not CKB devnet confirmation")
        );

        let response = route_empty(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/receive"),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/settle"),
            json!({ "payment_preimage": preimage }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["invoices"][0]["status"].as_str(), Some("paid"));
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("invoice-settled"))
        );
    }

    #[test]
    fn invoice_creation_rejects_excessive_expiry() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);

        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "too long",
                "payment_preimage": bytes32_hex(17),
                "expiry_secs": MAX_INVOICE_EXPIRY_SECS + 1,
                "asset": { "kind": "ckb" }
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("expiry_secs must be at most")
        );
    }

    #[test]
    fn decode_invoice_marks_status_received() {
        let local_pubkey = pubkey_from_scalar(1);
        let server = test_server(&local_pubkey);
        let created_at_unix = now_unix().unwrap();
        let payee_key = signing_key_from_scalar(9);
        let invoice = MorphInvoice::new_signed(
            NewMorphInvoice {
                network: MorphNetwork::Devnet,
                payee_node_id: blake2b256(
                    payee_key.verifying_key().to_encoded_point(true).as_bytes(),
                ),
                channel_id: None,
                asset: MorphAsset::Ckb,
                amount: 100_000_000,
                created_at_unix,
                expires_at_unix: created_at_unix + 3600,
                payment_preimage: Some([11u8; 32]),
                payment_hash: None,
                description: "decoded invoice".to_string(),
            },
            &payee_key,
        )
        .unwrap();

        let response = route_json(
            &server,
            "POST",
            "/api/invoices/decode",
            json!({ "encoded_invoice": invoice.encode() }),
        );

        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let invoice_id = hex_prefixed(&invoice.invoice_id);
        let decoded = body["invoices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["invoice_id"].as_str() == Some(invoice_id.as_str()))
            .expect("decoded invoice should be returned");
        assert_eq!(decoded["status"].as_str(), Some("received"));
        assert!(decoded["received_at_unix"].as_u64().is_some());
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("invoice-received"))
        );
    }

    #[test]
    fn channel_api_flow_opens_splices_publishes_and_finalises() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        let channel_id = bytes32_hex(21);

        let response = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": channel_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "counterparty",
                "funding_context_id": bytes32_hex(22),
                "local": "100000000",
                "remote": "200000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/splice"),
            json!({
                "new_funding_epoch": 2,
                "new_funding_context_id": bytes32_hex(23)
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/publish"),
            json!({
                "funding_context_id": bytes32_hex(23),
                "state_number": 3
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/finalise"),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["channels"][0]["phase"].as_str(), Some("closed"));
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("channel-finalised"))
        );
    }

    #[test]
    fn ckb_channel_amounts_must_fit_u64_quantities() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);

        let response = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": bytes32_hex(81),
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "too-large",
                "funding_context_id": bytes32_hex(82),
                "local": (u128::from(u64::MAX) + 1).to_string(),
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );

        assert_eq!(response.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("must fit in a u64")
        );
    }

    #[test]
    fn factory_api_flow_opens_advances_and_materialises_child() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let server = test_server(&local_pubkey);
        let factory_id = bytes32_hex(31);
        let child_id = bytes32_hex(32);

        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/advance"),
            json!({ "new_update_number": 2 }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "member",
                "funding_context_id": bytes32_hex(33),
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["factories"][0]["update_number"].as_u64(), Some(2));
        assert_eq!(
            body["factories"][0]["materialised_child_channels"][0].as_str(),
            Some(child_id.as_str())
        );
        let child = body["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|channel| channel["channel_id"].as_str() == Some(child_id.as_str()))
            .expect("materialised child should be projected as a channel");
        assert_eq!(child["factory_id"].as_str(), Some(factory_id.as_str()));
        assert_eq!(
            body["model"]["profile"].as_str(),
            Some("morph-v3-conditional-batch")
        );
        assert_eq!(
            body["model"]["hub_role"].as_str(),
            Some("local_operator_projection")
        );
        assert_eq!(
            body["model"]["factory_min_participants"].as_u64(),
            Some(FACTORY_MIN_PARTICIPANTS as u64)
        );
        assert_eq!(
            body["model"]["factory_max_participants"].as_u64(),
            Some(FACTORY_MAX_PARTICIPANTS as u64)
        );
        assert_eq!(
            body["model"]["chain_actions_enabled"].as_bool(),
            Some(false)
        );
        assert_eq!(
            body["model"]["provider_edges_exposed"].as_bool(),
            Some(false)
        );
        assert!(
            body["completed_flows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flow| flow.as_str() == Some("factory-child"))
        );
    }

    #[test]
    fn hub_api_can_complete_all_required_business_flows() {
        let local_pubkey = pubkey_from_scalar(1);
        let peer_pubkey = pubkey_from_scalar(2);
        let channel_peer_pubkey = pubkey_from_scalar(3);
        let server = test_server(&local_pubkey);

        let response = route_json(
            &server,
            "POST",
            "/api/peers",
            json!({
                "pubkey": peer_pubkey,
                "alias": "all-flow-peer"
            }),
        );
        assert_eq!(response.status, 200);

        let preimage = bytes32_hex(41);
        let response = route_json(
            &server,
            "POST",
            "/api/invoices",
            json!({
                "amount": "100000000",
                "description": "all-flow invoice",
                "payment_preimage": preimage,
                "expiry_secs": 3600,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let invoice_id = body["invoices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|invoice| invoice["description"].as_str() == Some("all-flow invoice"))
            .and_then(|invoice| invoice["invoice_id"].as_str())
            .unwrap()
            .to_string();

        let response = route_empty(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/receive"),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/invoices/{invoice_id}/settle"),
            json!({ "payment_preimage": preimage }),
        );
        assert_eq!(response.status, 200);

        let channel_id = bytes32_hex(51);
        let funding_context_id = bytes32_hex(52);
        let spliced_funding_context_id = bytes32_hex(53);
        let response = route_json(
            &server,
            "POST",
            "/api/channels",
            json!({
                "channel_id": channel_id,
                "counterparty_pubkey": channel_peer_pubkey,
                "counterparty_alias": "all-flow-channel-peer",
                "funding_context_id": funding_context_id,
                "local": "100000000",
                "remote": "200000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/splice"),
            json!({
                "new_funding_epoch": 1,
                "new_funding_context_id": spliced_funding_context_id
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/publish"),
            json!({
                "funding_context_id": spliced_funding_context_id,
                "state_number": 2
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(
            &server,
            "POST",
            format!("/api/channels/{channel_id}/finalise"),
        );
        assert_eq!(response.status, 200);

        let factory_id = bytes32_hex(61);
        let child_channel_id = bytes32_hex(62);
        let response = route_json(
            &server,
            "POST",
            "/api/factories",
            json!({
                "factory_id": factory_id,
                "participant_pubkeys": [local_pubkey.as_str(), peer_pubkey.as_str()],
                "reserve": "500000000",
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/advance"),
            json!({ "new_update_number": 1 }),
        );
        assert_eq!(response.status, 200);

        let response = route_json(
            &server,
            "POST",
            format!("/api/factories/{factory_id}/materialise-child"),
            json!({
                "child_channel_id": child_channel_id,
                "counterparty_pubkey": peer_pubkey,
                "counterparty_alias": "all-flow-factory-peer",
                "funding_context_id": bytes32_hex(63),
                "local": "100000000",
                "remote": "100000000",
                "sponsor_budget": 1000000,
                "asset": { "kind": "ckb" }
            }),
        );
        assert_eq!(response.status, 200);

        let response = route_empty(&server, "GET", "/api/state");
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let missing_flows = body["missing_flows"].as_array().unwrap();
        assert!(
            missing_flows.is_empty(),
            "all required flows should complete, missing {missing_flows:?}"
        );

        let required_flows = body["required_flows"].as_array().unwrap();
        let completed_flows = body["completed_flows"].as_array().unwrap();
        assert_eq!(completed_flows.len(), required_flows.len());
        for flow in required_flows {
            assert!(
                completed_flows.contains(flow),
                "required flow {flow:?} was not completed"
            );
        }
    }

    fn test_server(local_pubkey: &str) -> HubServer {
        test_server_with_options(local_pubkey, None, false, None)
    }

    fn test_server_with_watch_alert_file(
        local_pubkey: &str,
        watch_alert_file: PathBuf,
    ) -> HubServer {
        let mut server = test_server(local_pubkey);
        server.watch_alert_file = Some(watch_alert_file);
        server
    }

    fn test_server_with_options(
        local_pubkey: &str,
        auth_token: Option<&str>,
        allow_state_restore: bool,
        cors_origin: Option<&str>,
    ) -> HubServer {
        let path = std::env::temp_dir().join(format!(
            "morph-hub-test-{}-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            TEST_STATE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        let store = HubStore::load_or_create(path, local_pubkey, MorphNetwork::Devnet).unwrap();
        let auth_token = parse_hub_auth_token(auth_token.map(str::to_string)).unwrap();
        let allow_unauthenticated_loopback = auth_token.is_none();
        HubServer {
            store: Arc::new(Mutex::new(store)),
            rpc_cache: Arc::new(Mutex::new(RpcHealthCache::default())),
            watch_alert_cache: Arc::new(Mutex::new(WatchtowerAlertCache::default())),
            active_connections: Arc::new(AtomicUsize::new(0)),
            active_mutations: Arc::new(AtomicUsize::new(0)),
            active_sse_streams: Arc::new(AtomicUsize::new(0)),
            request_counter: Arc::new(AtomicU64::new(1)),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
            ui_dir: PathBuf::from("ui/morph-hub/dist"),
            ckb_rpc_url: None,
            watch_alert_file: None,
            invoice_signing_key: test_signing_key_for_pubkey(local_pubkey),
            auth_token,
            allow_unauthenticated_loopback,
            allow_state_restore,
            cors_origin: cors_origin.map(str::to_string),
        }
    }

    fn route_restore_state_file(server: &HubServer, persisted: serde_json::Value) -> HttpResponse {
        let preview = route_json(server, "POST", "/api/state-file/preview", persisted.clone());
        let confirmation_hash = if preview.status == 200 {
            let body: serde_json::Value = serde_json::from_slice(&preview.body).unwrap();
            body["confirmation_hash"]
                .as_str()
                .expect("preview should include confirmation_hash")
                .to_string()
        } else {
            String::new()
        };
        route_json(
            server,
            "PUT",
            "/api/state-file",
            json!({
                "state": persisted,
                "confirmation_hash": confirmation_hash
            }),
        )
    }

    fn route_json(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        value: serde_json::Value,
    ) -> HttpResponse {
        route_json_with_headers(
            server,
            method,
            path,
            value,
            std::iter::empty::<(&str, &str)>(),
        )
    }

    fn route_json_with_headers(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        value: serde_json::Value,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpResponse {
        server.route(HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.to_string()))
                .collect(),
            body: serde_json::to_vec(&value).unwrap(),
        })
    }

    fn route_empty(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> HttpResponse {
        route_empty_with_headers(server, method, path, std::iter::empty::<(&str, &str)>())
    }

    fn route_empty_with_headers(
        server: &HubServer,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpResponse {
        server.route(request_empty(method, path, headers))
    }

    fn response_header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn request_empty(
        method: impl Into<String>,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn state_file_mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn hex_repeat(ch: char) -> String {
        format!("0x{}", ch.to_string().repeat(64))
    }

    fn bytes32_hex(seed: u8) -> String {
        let hex = (0..32)
            .map(|offset| format!("{:02x}", seed.wrapping_add(offset)))
            .collect::<String>();
        format!("0x{hex}")
    }

    fn temp_file_path(label: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "morph-hub-test-{label}-{}-{}-{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            TEST_STATE_COUNTER.fetch_add(1, Ordering::Relaxed),
            extension
        ))
    }

    fn state_backup_paths(path: &Path) -> Vec<PathBuf> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let prefix = format!("{}.bak.", path.file_name().unwrap().to_string_lossy());
        let mut backups = fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .collect::<Vec<_>>();
        backups.sort();
        backups
    }

    fn pubkey_from_scalar(value: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap();
        hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    fn signing_key_from_scalar(value: u8) -> k256::ecdsa::SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        k256::ecdsa::SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    fn test_signing_key_for_pubkey(pubkey: &str) -> Option<k256::ecdsa::SigningKey> {
        (1..=u8::MAX)
            .find(|value| pubkey_from_scalar(*value) == pubkey)
            .map(signing_key_from_scalar)
    }
}
