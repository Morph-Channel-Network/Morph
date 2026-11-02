export type Hex32 = `0x${string}`;
export type Pubkey = string;
export type Network = 'devnet' | 'testnet' | 'mainnet';
export type Phase = 'funding' | 'active' | 'settling' | 'closed';
export type InvoiceStatus = 'open' | 'received' | 'paid' | 'cancelled' | 'expired';
export type EventSeverity = 'info' | 'warning' | 'critical';
export type RpcStatus = 'connected' | 'degraded' | 'offline' | 'not_configured';
export type ProvenanceSource = 'hub_state_file' | 'watchtower_alert_file';
export type ChainStatus = 'not_chain_verified' | 'watchtower_alert';
export type WatchAlertSeverity = 'info' | 'warning' | 'critical';
export type HubScope = 'read' | 'write' | 'restore' | 'sign';
export type WatchAlertEvent =
  | 'chain_reorg_detected'
  | 'recovery_data_invalid'
  | 'publication_failed'
  | 'older_state_detected'
  | 'publication_submitted'
  | 'splice_detected'
  | 'splice_package_stale'
  | 'splice_publication_submitted'
  | 'scan_idle';
export type FlowKey =
  | 'peer'
  | 'invoice-created'
  | 'invoice-received'
  | 'invoice-settled'
  | 'channel-opened'
  | 'state-published'
  | 'channel-finalised'
  | 'channel-spliced'
  | 'factory-opened'
  | 'factory-advanced'
  | 'factory-child';

export interface Asset {
  kind: 'ckb' | 'xudt';
  type_hash?: Hex32;
}

export const MAX_CKB_INVOICE_AMOUNT = '18446744073709551615';

export interface Balance {
  asset: Asset;
  local: string;
  remote: string;
  pending: string;
}

export interface RecordProvenance {
  source: ProvenanceSource;
  chain_status: ChainStatus;
  label: string;
  message: string;
}

export interface HubSecurity {
  auth_required: boolean;
  auth_mode: 'scoped_bearer' | 'explicit_unauthenticated_loopback';
  auth_scopes: HubScope[];
  single_operator: boolean;
  state_restore_enabled: boolean;
  invoice_signing_enabled: boolean;
  cors_origin?: string | null;
  max_concurrent_connections: number;
  max_concurrent_mutations: number;
  max_concurrent_event_streams: number;
  mutation_rate_limit_per_minute: number;
  max_invoice_expiry_secs: number;
}

export interface HubModel {
  profile: string;
  hub_role: 'local_operator_projection';
  factory_authority: 'factory_state_and_vault';
  channel_authority: 'state_and_vault';
  routing_role: 'external_optional_provider';
  agent_role: 'application_sidecar';
  factory_min_participants: number;
  factory_max_participants: number;
  chain_actions_enabled: boolean;
  factory_rights_exposed: boolean;
  provider_edges_exposed: boolean;
  rgbpp_evidence_exposed: boolean;
  agent_receipts_exposed: boolean;
}

export interface PeerRecord {
  pubkey: Pubkey;
  node_id: Hex32;
  alias: string;
  provenance: RecordProvenance;
}

export interface ChannelRecord {
  channel_id: Hex32;
  factory_id?: Hex32 | null;
  counterparty_pubkey: Pubkey;
  counterparty_node_id: Hex32;
  funding_epoch: number;
  funding_context_id: Hex32;
  state_number: number;
  phase: Phase;
  balances: Balance[];
  sponsor_budget: number;
  provenance: RecordProvenance;
}

export interface InvoiceRecord {
  invoice_id: Hex32;
  encoded_invoice: string;
  status: InvoiceStatus;
  network: Network;
  payee_pubkey?: Pubkey;
  payee_node_id: Hex32;
  channel_id?: Hex32;
  asset: Asset;
  amount: string;
  created_at_unix: number;
  expires_at_unix: number;
  payment_hash: Hex32;
  description: string;
  received_at_unix?: number;
  paid_at_unix?: number;
  cancelled_at_unix?: number;
  provenance: RecordProvenance;
}

export interface FactoryRecord {
  factory_id: Hex32;
  participant_pubkeys: Pubkey[];
  participant_node_ids: Hex32[];
  update_number: number;
  reserve_balances: Balance[];
  materialised_child_channels: Hex32[];
  provenance: RecordProvenance;
}

export interface ConditionalBatchPackage {
  schema: 'morph.conditional_batch_package';
  channel_id: Hex32;
  funding_context_id: Hex32;
  state_number: number;
  batch_id: Hex32;
  application_context_commitment: Hex32;
  input_since: number;
  descriptor_commitment: Hex32;
  resolved_capacities: [number, number];
  transfers: unknown[];
  resolutions: unknown[];
}

export interface HubEvent {
  id: number;
  severity: EventSeverity;
  event: string;
  subject_id?: Hex32;
  message: string;
  created_at_unix: number;
  provenance: RecordProvenance;
}

export interface RpcHealth {
  status: RpcStatus;
  url?: string | null;
  tip_height?: number | null;
  chain?: string | null;
  message?: string | null;
}

export interface WatchtowerAlertRecord {
  schema: string;
  created_unix_ms: number;
  channel_id: Hex32;
  severity: WatchAlertSeverity;
  event: WatchAlertEvent;
  message: string;
  selected_state_number: number;
  observed_state_number?: number | null;
  observed_out_point?: string | null;
  publication_tx_hash?: Hex32 | null;
  selected_funding_anchor?: Hex32 | null;
  observed_funding_anchor?: Hex32 | null;
  selected_funding_context_id?: Hex32 | null;
  observed_funding_context_id?: Hex32 | null;
  scanned_to_block: number;
  next_from_block: number;
  provenance: RecordProvenance;
}

export interface WatchtowerState {
  configured: boolean;
  alert_file?: string | null;
  file_exists: boolean;
  alerts: WatchtowerAlertRecord[];
  last_error?: string | null;
  provenance: RecordProvenance;
}

export interface MultiAssetRecoverySummary {
  package_id: Hex32;
  channel_id: Hex32;
  funding_context_id: Hex32;
  state_number: string;
  phase: 'active' | 'settling';
  vaults_bound: boolean;
  vault_count: number;
  witness_bytes: number;
  dependency_count: number;
  state_carrier_capacity: string;
  signer_pubkeys: [string, string];
  assets: Array<{ type_hash: Hex32 | null; reserve: string; business_ckb: string; amount: string }>;
}

export interface NodeState {
  pubkey: Pubkey;
  node_id: Hex32;
  network: Network;
  state_path: string;
  rpc: RpcHealth;
  security: HubSecurity;
  model: HubModel;
  provenance: RecordProvenance;
  watchtower: WatchtowerState;
  peers: PeerRecord[];
  channels: ChannelRecord[];
  invoices: InvoiceRecord[];
  factories: FactoryRecord[];
  conditional_batches: ConditionalBatchPackage[];
  multi_asset_packages: MultiAssetRecoverySummary[];
  multi_asset_package_count: number;
  events: HubEvent[];
  required_flows: FlowKey[];
  completed_flows: FlowKey[];
  missing_flows: FlowKey[];
}

export const emptyState: NodeState = {
  pubkey: '',
  node_id: '0x0000000000000000000000000000000000000000000000000000000000000000',
  network: 'devnet',
  state_path: '',
  rpc: { status: 'offline', message: 'API not loaded' },
  security: {
    auth_required: false,
    auth_mode: 'explicit_unauthenticated_loopback',
    auth_scopes: [],
    single_operator: true,
    state_restore_enabled: false,
    invoice_signing_enabled: false,
    cors_origin: null,
    max_concurrent_connections: 0,
    max_concurrent_mutations: 0,
    max_concurrent_event_streams: 0,
    mutation_rate_limit_per_minute: 0,
    max_invoice_expiry_secs: 604800,
  },
  model: {
    profile: 'morph-v3-conditional-batch',
    hub_role: 'local_operator_projection',
    factory_authority: 'factory_state_and_vault',
    channel_authority: 'state_and_vault',
    routing_role: 'external_optional_provider',
    agent_role: 'application_sidecar',
    factory_min_participants: 2,
    factory_max_participants: 16,
    chain_actions_enabled: false,
    factory_rights_exposed: false,
    provider_edges_exposed: false,
    rgbpp_evidence_exposed: false,
    agent_receipts_exposed: false,
  },
  provenance: {
    source: 'hub_state_file',
    chain_status: 'not_chain_verified',
    label: 'Local only',
    message: 'API not loaded',
  },
  watchtower: {
    configured: false,
    alert_file: null,
    file_exists: false,
    alerts: [],
    last_error: null,
    provenance: {
      source: 'hub_state_file',
      chain_status: 'not_chain_verified',
      label: 'Local only',
      message: 'API not loaded',
    },
  },
  peers: [],
  channels: [],
  invoices: [],
  factories: [],
  conditional_batches: [],
  multi_asset_packages: [],
  multi_asset_package_count: 0,
  events: [],
  required_flows: [],
  completed_flows: [],
  missing_flows: [],
};

export function formatAmount(value: string | number | bigint, asset: Asset): string {
  const amount = typeof value === 'bigint' ? value : BigInt(String(value || '0'));
  if (asset.kind === 'ckb') {
    const whole = amount / 100000000n;
    const frac = (amount % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return `${whole}${frac ? `.${frac}` : ''} CKB`;
  }
  return `${amount.toLocaleString()} xUDT`;
}

export function formatBalance(balance?: Balance): string {
  if (!balance) return '0 CKB';
  const total = BigInt(balance.local) + BigInt(balance.remote) + BigInt(balance.pending);
  return formatAmount(total, balance.asset);
}

export function hasHubScope(security: HubSecurity, scope: HubScope): boolean {
  return security.auth_mode === 'explicit_unauthenticated_loopback' || security.auth_scopes.includes(scope);
}

export function shortHex(value?: string): string {
  if (!value) return '';
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

export function formatTime(unix?: number): string {
  if (!unix) return '—';
  return new Date(unix * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatTimeMs(unixMs?: number): string {
  if (!unixMs) return '—';
  return formatTime(Math.floor(unixMs / 1000));
}

export function assetLabel(asset: Asset): string {
  return asset.kind === 'ckb' ? 'CKB' : `xUDT ${shortHex(asset.type_hash)}`;
}

export function assertHex32(value: string, label: string): Hex32 {
  const trimmed = value.trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error(`${label} must be a 32-byte 0x-prefixed hex value.`);
  }
  if (/^0x0{64}$/.test(trimmed)) {
    throw new Error(`${label} must not be zero.`);
  }
  return trimmed as Hex32;
}

export function assertPubkey(value: string, label: string): Pubkey {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.startsWith('0x')) {
    throw new Error(`${label} must be 66 hex characters without 0x, matching Fiber RPC convention.`);
  }
  if (!/^[0-9a-f]{66}$/.test(trimmed)) {
    throw new Error(`${label} must be a 33-byte compressed secp256k1 pubkey encoded as 66 hex characters.`);
  }
  if (!/^(02|03)/.test(trimmed)) {
    throw new Error(`${label} must be a compressed secp256k1 pubkey starting with 02 or 03.`);
  }
  return trimmed;
}

export function assertRemotePubkey(value: string, localPubkey: Pubkey, label: string): Pubkey {
  const pubkey = assertPubkey(value, label);
  if (localPubkey && pubkey === localPubkey) {
    throw new Error(`${label} must not be the local pubkey.`);
  }
  return pubkey;
}

export function parsePubkeyList(value: string, label: string): Pubkey[] {
  const parts = value
    .split(/[\s,]+/)
    .map(part => part.trim())
    .filter(Boolean);
  if (parts.length === 0) throw new Error(`${label} must include at least one pubkey.`);
  const pubkeys = parts.map(part => assertPubkey(part, label));
  if (new Set(pubkeys).size !== pubkeys.length) {
    throw new Error(`${label} must not contain duplicate pubkeys.`);
  }
  return pubkeys;
}

export function assertIncludesPubkey(values: Pubkey[], required: Pubkey, label: string): void {
  if (required && !values.includes(required)) {
    throw new Error(`${label} must include the local pubkey.`);
  }
}

export function normaliseAsset(asset: Asset): Asset {
  if (asset.kind === 'ckb') return { kind: 'ckb' };
  return { kind: 'xudt', type_hash: assertHex32(asset.type_hash ?? '', 'Asset type hash') };
}

export function assertPositiveInteger(value: string, label: string): string {
  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) throw new Error(`${label} must be an unsigned integer.`);
  if (BigInt(trimmed) === 0n) throw new Error(`${label} must be greater than zero.`);
  return trimmed;
}

export function assertInvoiceAmount(value: string, asset: Asset): string {
  const amount = assertPositiveInteger(value, 'Amount');
  if (asset.kind === 'ckb' && BigInt(amount) > BigInt(MAX_CKB_INVOICE_AMOUNT)) {
    throw new Error(`Amount must be at most ${MAX_CKB_INVOICE_AMOUNT} shannons for CKB invoices.`);
  }
  return amount;
}

export function assertNonNegativeInteger(value: string, label: string): string {
  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) throw new Error(`${label} must be an unsigned integer.`);
  return trimmed;
}
