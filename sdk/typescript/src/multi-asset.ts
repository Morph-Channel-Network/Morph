import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";

export interface MultiAssetRecoveryPackage {
  schema: "morph.multi_asset_recovery_package.v1";
  header_hex: string;
  witness_hex: string;
  signature_witness_hex: string;
  state_carrier_capacity: string;
  cell_deps: Array<{ tx_hash: string; index: number; dep_type: "code" | "dep_group" }>;
}

export interface MultiAssetPackageSummary {
  package_id: string;
  channel_id: string;
  funding_context_id: string;
  state_number: string;
  phase: "active" | "settling";
  vaults_bound: boolean;
  vault_count: number;
  witness_bytes: number;
  dependency_count: number;
  state_carrier_capacity: string;
  signer_pubkeys: [string, string];
  assets: Array<{ type_hash: string | null; reserve: string; business_ckb: string; amount: string }>;
}

const MAX_U64 = (1n << 64n) - 1n;
const MAX_VAULTS = 8;
const MAX_SCRIPT_BYTES = 512;
const MAX_WITNESS_BYTES = 28 + 4 + 8 * 97 + 100 + 8 * 97 + 8 * 36 + 14 * 516;
const utf8 = new TextEncoder();

function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new TypeError(`invalid multi-asset package: ${message}`);
}

function bytes(raw: string, max: number): Uint8Array {
  requireValue(typeof raw === "string" && raw.length <= 2 + 2 * max && /^0x(?:[0-9a-f]{2})*$/.test(raw), "noncanonical hex or byte limit exceeded");
  return Uint8Array.from(raw.slice(2).match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function hex(raw: Uint8Array): string {
  return `0x${Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function join(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function hash(...parts: Uint8Array[]): Uint8Array {
  return blake2b(join(...parts), { dkLen: 32, personalization: utf8.encode("ckb-default-hash") });
}

function domainHash(domain: string, ...parts: Uint8Array[]): Uint8Array {
  return hash(utf8.encode(domain), ...parts);
}

function same(a: Uint8Array, b: Uint8Array): boolean { return hex(a) === hex(b); }
function zero(raw: Uint8Array): boolean { return raw.every((byte) => byte === 0); }

function unsigned(raw: Uint8Array, offset: number, length: number): bigint {
  requireValue(offset >= 0 && offset + length <= raw.length, "truncated integer");
  let value = 0n;
  for (let i = length - 1; i >= 0; i--) value = (value << 8n) | BigInt(raw[offset + i]!);
  return value;
}
function u16(raw: Uint8Array, offset: number): number { return Number(unsigned(raw, offset, 2)); }
function u32(raw: Uint8Array, offset: number): number { return Number(unsigned(raw, offset, 4)); }
function little(value: number | bigint, length: number): Uint8Array {
  let remaining = BigInt(value);
  return Uint8Array.from({ length }, () => { const byte = Number(remaining & 255n); remaining >>= 8n; return byte; });
}

interface Asset { kind: number; type: Uint8Array; key: string }
interface Allocation { reserve: bigint; business: bigint; amount: bigint; capacity: bigint }
interface Vault { asset: Asset; lock: Uint8Array; value: Allocation }

function asset(raw: Uint8Array, offset: number): Asset {
  requireValue(offset + 33 <= raw.length, "truncated asset");
  const kind = raw[offset]!;
  const type = raw.slice(offset + 1, offset + 33);
  requireValue((kind === 0 && zero(type)) || (kind === 1 && !zero(type)), "unknown asset identity");
  return { kind, type, key: hex(raw.slice(offset, offset + 33)) };
}

function allocation(raw: Uint8Array, offset: number, id: Asset, vault: boolean): Allocation {
  const reserve = unsigned(raw, offset, 8);
  const business = unsigned(raw, offset + 8, 8);
  const amount = unsigned(raw, offset + 16, 16);
  const capacity = reserve + business;
  requireValue(capacity <= MAX_U64 && (id.kind !== 0 || amount === 0n)
    && (capacity !== 0n || amount === 0n) && (capacity === 0n || reserve > 0n)
    && (!vault || (capacity > 0n && (id.kind === 0 || amount > 0n))), "invalid allocation or overflow");
  return { reserve, business, amount, capacity };
}

function scriptOccupied(raw: Uint8Array): bigint {
  requireValue(raw.length >= 53 && raw.length <= MAX_SCRIPT_BYTES
    && u32(raw, 0) === raw.length && u32(raw, 4) === 16 && u32(raw, 8) === 48
    && u32(raw, 12) === 49 && u32(raw, 49) === raw.length - 53
    && [0, 1, 2, 4].includes(raw[48]!), "noncanonical CKB Script");
  return BigInt(33 + raw.length - 53);
}

function occupied(lock: Uint8Array, type?: Uint8Array): bigint {
  return (8n + scriptOccupied(lock) + (type === undefined ? 0n : scriptOccupied(type) + 16n)) * 100_000_000n;
}

function recoveryParts(witness: Uint8Array): { manifest: Uint8Array; descriptor: Uint8Array; points: Uint8Array; pointCount: number; scripts: Uint8Array[] } {
  requireValue(witness.length >= 28 && same(witness.slice(0, 8), utf8.encode("MORPHMA!"))
    && u16(witness, 8) === 1 && u16(witness, 10) === 0 && u16(witness, 22) === 0, "invalid recovery witness");
  const manifestEnd = 28 + u32(witness, 12);
  const descriptorEnd = manifestEnd + u32(witness, 16);
  const pointCount = u16(witness, 20);
  const scriptsStart = descriptorEnd + 36 * pointCount;
  requireValue(pointCount <= MAX_VAULTS && scriptsStart + u32(witness, 24) === witness.length, "truncated recovery evidence");
  const scripts: Uint8Array[] = [];
  let cursor = scriptsStart;
  while (cursor < witness.length) {
    const len = u32(witness, cursor);
    requireValue(scripts.length < 6 + MAX_VAULTS && len >= 53 && len <= MAX_SCRIPT_BYTES && cursor + 4 + len <= witness.length, "invalid script evidence length");
    const script = witness.slice(cursor + 4, cursor + 4 + len);
    scriptOccupied(script);
    scripts.push(script);
    cursor += 4 + len;
  }
  return {manifest: witness.slice(28, manifestEnd), descriptor: witness.slice(manifestEnd, descriptorEnd), points: witness.slice(descriptorEnd, scriptsStart), pointCount, scripts};
}

/** Verify both signatures, all commitments, provenance, per-asset conservation,
 * and occupied-capacity funding without converting u64/u128 values to Number.
 * Chain liveness, confirmations, and deployed code approval require an RPC and
 * the operator's release policy in addition to this local evidence check. */
export function inspectMultiAssetPackage(value: MultiAssetRecoveryPackage): MultiAssetPackageSummary {
  return inspectPackage(value, true);
}

interface PackageEvidence {
  summary: MultiAssetPackageSummary;
  header: Uint8Array;
  witness: Uint8Array;
  descriptor: Uint8Array;
  scripts: Uint8Array[];
  vaults: Vault[];
  payouts: [Allocation, Allocation][];
  publicKeys: readonly [Uint8Array, Uint8Array];
}
function inspectPackage(value: MultiAssetRecoveryPackage, verifySignatures: boolean): MultiAssetPackageSummary {
  return inspectEvidence(value, verifySignatures).summary;
}

function inspectEvidence(value: MultiAssetRecoveryPackage, verifySignatures: boolean): PackageEvidence {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.multi_asset_recovery_package.v1", "unsupported schema");
  requireValue(Object.keys(value).sort().join(",") === "cell_deps,header_hex,schema,signature_witness_hex,state_carrier_capacity,witness_hex", "unknown package fields");
  requireValue(Array.isArray(value.cell_deps) && value.cell_deps.length >= 1 && value.cell_deps.length <= 64, "incomplete code dependencies");
  let previousDependency: { tx_hash: string; index: number } | undefined;
  for (const dep of value.cell_deps) {
    requireValue(typeof dep === "object" && dep !== null && Object.keys(dep).sort().join(",") === "dep_type,index,tx_hash"
      && typeof dep.tx_hash === "string" && /^0x[0-9a-f]{64}$/.test(dep.tx_hash) && !zero(bytes(dep.tx_hash, 32))
      && Number.isSafeInteger(dep.index) && dep.index >= 0 && dep.index <= 0xffffffff
      && (dep.dep_type === "code" || dep.dep_type === "dep_group"), "invalid code dependency");
    requireValue(previousDependency === undefined || previousDependency.tx_hash < dep.tx_hash
      || (previousDependency.tx_hash === dep.tx_hash && previousDependency.index < dep.index), "duplicate or unordered code dependencies");
    previousDependency = dep;
  }
  const header = bytes(value.header_hex, 318);
  requireValue(header.length === 318 && u16(header, 0) === 1 && u16(header, 34) === 1
    && header[116] === 1 && [1, 2].includes(header[117]!) && u16(header, 214) === 4
    && u16(header, 248) === 2 && u16(header, 316) === 0, "unsupported State profile");
  requireValue(header[117] !== 2 || unsigned(header, 108, 8) > 0n, "settling recovery requires positive state number");
  const count = u16(header, 314);
  const contentRoot = header.slice(250, 282);
  const pointRoot = header.slice(282, 314);
  const bound = !zero(pointRoot);
  requireValue(!verifySignatures || bound || unsigned(header, 68, 8) !== 0n,
    "root creation requires transaction-bound funding authorization");
  requireValue(count >= 1 && count <= MAX_VAULTS && !zero(contentRoot)
    && (header[117] !== 2 || bound), "invalid Vault context");
  const witness = bytes(value.witness_hex, MAX_WITNESS_BYTES);
  const { manifest, descriptor, points, pointCount, scripts } = recoveryParts(witness);
  requireValue(manifest.length === 4 + count * 97 && u16(manifest, 0) === 1 && manifest[2] === count && manifest[3] === 0, "invalid Vault manifest");
  requireValue(descriptor.length === 100 + count * 97 && u16(descriptor, 0) === 4 && descriptor[2] === count && descriptor[3] === 0, "invalid settlement descriptor");
  requireValue(same(domainHash("CKB_MORPH_MULTI_ASSET_VAULT_SET_V1", manifest), contentRoot)
    && same(domainHash("CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1", descriptor), header.slice(182, 214)), "manifest or descriptor commitment mismatch");
  const locks = [descriptor.slice(4, 36), descriptor.slice(36, 68), descriptor.slice(68, 100)];
  requireValue(!zero(locks[0]!) && hex(locks[0]!) < hex(locks[1]!) && !zero(locks[2]!), "invalid payout locks");
  const vaults: Vault[] = [];
  const payouts: [Allocation, Allocation][] = [];
  let total = 0n;
  for (let i = 0; i < count; i++) {
    const offset = 4 + i * 97;
    const id = asset(manifest, offset);
    const lock = manifest.slice(offset + 33, offset + 65);
    const funded = allocation(manifest, offset + 65, id, true);
    requireValue(!zero(lock) && (i === 0 || (vaults[i - 1]!.asset.key < id.key && same(vaults[0]!.lock, lock))), "duplicate or unordered Vault assets");
    total += funded.capacity;
    requireValue(total <= MAX_U64, "total capacity overflow");
    vaults.push({ asset: id, lock, value: funded });
    const payoutOffset = 100 + i * 97;
    requireValue(asset(descriptor, payoutOffset).key === id.key, "settlement asset mismatch");
    const a = allocation(descriptor, payoutOffset + 33, id, false);
    const b = allocation(descriptor, payoutOffset + 65, id, false);
    requireValue(a.reserve + b.reserve === funded.reserve && a.business + b.business === funded.business
      && a.amount + b.amount === funded.amount, "per-asset conservation mismatch");
    payouts.push([a, b]);
  }
  const typed = vaults.filter((vault) => vault.asset.kind === 1);
  requireValue(same(domainHash("CKB_MORPH_ASSET_REGISTRY_V1", little(typed.length, 8), ...typed.map((vault) => vault.asset.type)), header.slice(150, 182)), "asset registry mismatch");
  requireValue(bound ? pointCount === count : pointCount === 0, "incomplete OutPoint set");
  if (bound) {
    const seen = new Set<string>();
    for (let i = 0; i < count; i++) {
      const point = points.slice(i * 36, (i + 1) * 36);
      requireValue(!zero(point.slice(0, 32)) && !seen.has(hex(point)), "duplicate or invalid OutPoint");
      seen.add(hex(point));
    }
    requireValue(same(domainHash("CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1", contentRoot, little(count, 2), points), pointRoot), "exact OutPoint commitment mismatch");
  }
  requireValue(scripts.length === 6 + typed.length, "extra or missing script evidence");
  for (let i = 0; i < 3; i++) requireValue(same(hash(scripts[i]!), locks[i]!), "payout script identity mismatch");
  const vaultScript = scripts[3]!;
  const stateType = scripts[4]!;
  const stateLock = scripts[5]!;
  const vaultArgs = vaultScript.slice(53);
  requireValue(vaultArgs.length === 116 && same(vaultArgs.slice(0, 8), utf8.encode("MORPHMV!"))
    && u16(vaultArgs, 8) === 1 && u16(vaultArgs, 10) === 0
    && !zero(vaultArgs.slice(12, 44)) && (unsigned(vaultArgs, 44, 8) >> 56n) === 0x80n
    && same(vaultArgs.slice(52, 84), hash(stateType)) && same(vaultArgs.slice(84, 116), hash(stateLock))
    && [93,125].includes(stateType.length) && (stateType.length!==125 || !zero(stateType.slice(85,117))) && same(stateType.slice(53, 85), vaultArgs.slice(12, 44))
    && same(stateType.slice(-8), vaultArgs.slice(44, 52)) && same(stateLock.slice(53), hash(stateType))
    && same(vaultArgs.slice(12, 44), header.slice(76, 108)), "State/Vault script authority mismatch");
  const vaultHash = hash(vaultScript);
  for (let i = 0; i < 3; i++) requireValue(!same(hash(scripts[i]!), vaultHash) && !same(hash(scripts[i]!), hash(stateLock)), "payout retains channel authority");
  let typeIndex = 6;
  for (let i = 0; i < count; i++) {
    const vault = vaults[i]!;
    const type = vault.asset.kind === 1 ? scripts[typeIndex++]! : undefined;
    requireValue(same(vaultHash, vault.lock) && (type === undefined || same(hash(type), vault.asset.type)), "Vault/Type Script identity mismatch");
    requireValue(occupied(vaultScript, type) <= vault.value.reserve, "insufficient Vault reserve");
    for (let participant = 0; participant < 2; participant++) {
      const payout = payouts[i]![participant]!;
      if (payout.capacity === 0n) continue;
      requireValue(occupied(scripts[participant]!, payout.amount === 0n ? undefined : type) <= payout.reserve, "insufficient payout reserve");
    }
  }
  requireValue(typeof value.state_carrier_capacity === "string" && /^[1-9][0-9]{0,19}$/.test(value.state_carrier_capacity), "invalid carrier capacity");
  const carrier = BigInt(value.state_carrier_capacity);
  const stateOccupied = (8n + scriptOccupied(stateLock) + scriptOccupied(stateType) + 318n) * 100_000_000n;
  requireValue(carrier <= MAX_U64 && occupied(scripts[2]!) <= carrier && stateOccupied <= carrier, "insufficient State carrier capacity");
  const signatures = bytes(value.signature_witness_hex, 198);
  requireValue(signatures.length === 198 && u16(signatures, 0) === 1 && signatures[2] === 2 && signatures[3] === 2, "unsupported signatures");
  const publicKeys = [signatures.slice(4, 37), signatures.slice(101, 134)] as const;
  requireValue(hex(publicKeys[0]) < hex(publicKeys[1])
    && same(domainHash("CKB_MORPH_PARTICIPANTS", Uint8Array.of(2, 2), ...publicKeys), header.slice(118, 150)), "participant commitment mismatch");
  const digest = domainHash("CKB_MORPH_MULTI_ASSET_STATE_V1", header);
  for (let i = 0; verifySignatures && i < 2; i++) {
    requireValue(secp256k1.verify(signatures.slice(37 + i * 97, 101 + i * 97), digest, publicKeys[i]!, {
      prehash: false, lowS: true, format: "compact",
    }), "invalid participant signature");
  }
  const summary: MultiAssetPackageSummary = {
    package_id: hex(digest), channel_id: hex(header.slice(36, 68)),
    funding_context_id: hex(domainHash("CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1", header.slice(2, 34), header.slice(36, 68), header.slice(76, 108), contentRoot, pointRoot)),
    state_number: unsigned(header, 108, 8).toString(), phase: header[117] === 1 ? "active" : "settling",
    vaults_bound: bound, vault_count: count, witness_bytes: witness.length,
    dependency_count: value.cell_deps.length,
    state_carrier_capacity: value.state_carrier_capacity, signer_pubkeys: [hex(publicKeys[0]), hex(publicKeys[1])],
    assets: vaults.map((vault) => ({ type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type), reserve: vault.value.reserve.toString(), business_ckb: vault.value.business.toString(), amount: vault.value.amount.toString() })),
  };
  return {summary, header, witness, descriptor, scripts, vaults, payouts, publicKeys};
}


export interface MultiAssetProposal {
  schema: "morph.multi_asset_proposal.v1";
  base_state_digest: string;
  state_number: string;
  descriptor_hex: string;
  signing_digest: string;
}

export interface MultiAssetSignatureReceipt {
  schema: "morph.multi_asset_signature.v1";
  signing_digest: string;
  pubkey: string;
  signature: string;
}

export interface MultiAssetProposalInspection {
  summary: MultiAssetPackageSummary;
  participant_lock_hashes: [string, string];
  payouts: Array<{
    type_hash: string | null;
    allocations: [
      { reserve: string; business_ckb: string; amount: string },
      { reserve: string; business_ckb: string; amount: string },
    ];
  }>;
}

function proposalEvidence(base: MultiAssetRecoveryPackage, stateNumber: string, descriptorHex: string): MultiAssetRecoveryPackage {
  const current = inspectMultiAssetPackage(base);
  requireValue(current.phase === "settling" && current.vaults_bound, "proposal requires bound settling recovery");
  requireValue(typeof stateNumber === "string" && /^[1-9][0-9]{0,19}$/.test(stateNumber), "noncanonical proposal state number");
  const number = BigInt(stateNumber);
  requireValue(number <= MAX_U64 && number > BigInt(current.state_number), "proposal must advance state number without overflow");
  const descriptor = bytes(descriptorHex, 100 + MAX_VAULTS * 97);
  const header = bytes(base.header_hex, 318);
  header.set(little(number, 8), 108);
  header.set(domainHash("CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1", descriptor), 182);
  const old = bytes(base.witness_hex, MAX_WITNESS_BYTES);
  const manifestEnd = 28 + u32(old, 12);
  const descriptorEnd = manifestEnd + u32(old, 16);
  const prefix = old.slice(0, 28);
  prefix.set(little(descriptor.length, 4), 16);
  const witness = join(prefix, old.slice(28, manifestEnd), descriptor, old.slice(descriptorEnd));
  return { ...base, header_hex: hex(header), witness_hex: hex(witness) };
}

/** Construct a proposal for explicit peer review. This stateless helper does
 * not replace a durable signer reservation or implement anti-rollback storage. */
export function createMultiAssetProposal(base: MultiAssetRecoveryPackage, stateNumber: string, descriptorHex: string): MultiAssetProposal {
  const summary = inspectMultiAssetPackage(base);
  const evidence = proposalEvidence(base, stateNumber, descriptorHex);
  // Only the new signatures are absent; all content and the old authenticated
  // participant identities are independently verified before requesting a vote.
  const next = inspectPackage(evidence, false);
  return { schema: "morph.multi_asset_proposal.v1", base_state_digest: summary.package_id,
    state_number: stateNumber, descriptor_hex: descriptorHex, signing_digest: next.package_id };
}

/** Inspect exact per-asset payouts without requiring signatures for the new
 * proposal. The base recovery package always requires both valid signatures. */
export function inspectMultiAssetProposal(base: MultiAssetRecoveryPackage, proposal: MultiAssetProposal): MultiAssetProposalInspection {
  requireValue(typeof proposal === "object" && proposal !== null && proposal.schema === "morph.multi_asset_proposal.v1"
    && Object.keys(proposal).sort().join(",") === "base_state_digest,descriptor_hex,schema,signing_digest,state_number", "unsupported proposal fields");
  const current = inspectMultiAssetPackage(base);
  requireValue(proposal.base_state_digest === current.package_id, "proposal does not extend current signed state");
  const evidence = proposalEvidence(base, proposal.state_number, proposal.descriptor_hex);
  const summary = inspectPackage(evidence, false);
  requireValue(summary.package_id === proposal.signing_digest, "proposal signing digest mismatch");
  const descriptor = bytes(proposal.descriptor_hex, 100 + MAX_VAULTS * 97);
  const payouts = summary.assets.map((_, index) => {
    const offset = 100 + index * 97;
    const id = asset(descriptor, offset);
    const values = [allocation(descriptor, offset + 33, id, false), allocation(descriptor, offset + 65, id, false)];
    return { type_hash: id.kind === 0 ? null : hex(id.type),
      allocations: values.map(value => ({ reserve: value.reserve.toString(), business_ckb: value.business.toString(), amount: value.amount.toString() })) as MultiAssetProposalInspection["payouts"][number]["allocations"] };
  });
  return { summary, participant_lock_hashes: [hex(descriptor.slice(4, 36)), hex(descriptor.slice(36, 68))], payouts };
}

export function inspectMultiAssetProposalSignature(base: MultiAssetRecoveryPackage, proposal: MultiAssetProposal, signature: MultiAssetSignatureReceipt): { signer_pubkey: string; signing_digest: string } {
  const inspected = inspectMultiAssetProposal(base, proposal);
  return verifyReceipt(proposal.signing_digest, inspected.summary.signer_pubkeys, signature);
}

export interface MultiAssetRootDraft {
  schema: "morph.multi_asset_root_draft.v1";
  transaction_hex: string;
  participants: [string, string];
}
export type MultiAssetFundingTarget = "exit" | "creation";
export interface MultiAssetRootInspection {
  transaction_hash: string;
  chain_id: string;
  channel_id: string;
  funding_context_id: string;
  creation_digest: string;
  exit_digest: string;
  state_carrier_capacity: string;
  participants: [string, string];
  participant_lock_hashes: [string, string];
  vault_outpoints: Array<{tx_hash: string; index: number}>;
  assets: MultiAssetPackageSummary["assets"];
  payouts: MultiAssetProposalInspection["payouts"];
  input_count: number;
  output_count: number;
}
export interface MultiAssetRootFunding {
  schema: "morph.multi_asset_root_funding.v1";
  transaction_hex: string;
  recovery_package: MultiAssetRecoveryPackage;
}

const MAX_FUNDING_BYTES = 256 * 1024;
function table(raw: Uint8Array, count: number): Uint8Array[] {
  requireValue(raw.length >= 4 * (count + 1) && u32(raw, 0) === raw.length && u32(raw, 4) === 4 * (count + 1), "noncanonical Molecule table");
  const offsets = Array.from({length: count}, (_, i) => u32(raw, 4 + i * 4));
  offsets.push(raw.length);
  requireValue(offsets.every((offset, i) => offset <= raw.length && (i === 0 || offset >= offsets[i - 1]!)), "invalid Molecule offsets");
  return offsets.slice(0, -1).map((offset, i) => raw.slice(offset, offsets[i + 1]));
}
function dynamic(raw: Uint8Array, max: number): Uint8Array[] {
  requireValue(raw.length >= 4 && u32(raw, 0) === raw.length, "invalid Molecule vector");
  if (raw.length === 4) return [];
  const first = u32(raw, 4);
  requireValue(first >= 8 && first % 4 === 0 && first / 4 - 1 <= max, "Molecule vector exceeds count bound");
  return table(raw, first / 4 - 1);
}
function fixed(raw: Uint8Array, size: number, max: number): Uint8Array[] {
  const count = u32(raw, 0);
  requireValue(count <= max && raw.length === 4 + size * count, "invalid Molecule fixed vector");
  return Array.from({length: count}, (_, i) => raw.slice(4 + i * size, 4 + (i + 1) * size));
}
function byteVector(raw: Uint8Array): Uint8Array {
  requireValue(raw.length >= 4 && u32(raw, 0) === raw.length - 4, "invalid Molecule Bytes");
  return raw.slice(4);
}
function encodeTable(fields: Uint8Array[]): Uint8Array {
  let offset = 4 * (fields.length + 1);
  const offsets = fields.map((field) => { const start = offset; offset += field.length; return little(start, 4); });
  return join(little(offset, 4), ...offsets, ...fields);
}
function encodeDynamic(fields: Uint8Array[]): Uint8Array { return fields.length === 0 ? little(4, 4) : encodeTable(fields); }
function encodeBytes(raw: Uint8Array): Uint8Array { return join(little(raw.length, 4), raw); }
interface TransactionEvidence {
  raw: Uint8Array;
  fields: Uint8Array[];
  witnesses: Uint8Array[];
  witnessFields: Uint8Array[];
  inputs: Uint8Array[];
  outputs: Array<{capacity: bigint; lock: Uint8Array; type: Uint8Array | undefined; data: Uint8Array}>;
  dependencies: MultiAssetRecoveryPackage["cell_deps"];
}
function transactionEvidence(raw: Uint8Array, emptyMorphWitness = false): TransactionEvidence {
  const [body, witnessVector] = table(raw, 2);
  const fields = table(body!, 6);
  requireValue(fields[0]!.length === 4 && u32(fields[0]!, 0) === 0, "unsupported root transaction version");
  const dependencies = fixed(fields[1]!, 37, 64).map((dep) => {
    requireValue(dep[36] === 0 || dep[36] === 1, "unsupported dependency type");
    return {tx_hash: hex(dep.slice(0, 32)), index: u32(dep, 32), dep_type: dep[36] === 0 ? "code" as const : "dep_group" as const};
  }).sort((a, b) => a.tx_hash < b.tx_hash ? -1 : a.tx_hash > b.tx_hash ? 1 : a.index - b.index);
  fixed(fields[2]!, 32, 64);
  const inputs = fixed(fields[3]!, 44, 64);
  requireValue(inputs.length > 0 && dependencies.length > 0, "missing root inputs or dependencies");
  const seen = new Set<string>();
  for (const input of inputs) {
    const point = input.slice(8);
    requireValue(!zero(point.slice(0, 32)) && !seen.has(hex(point)), "duplicate or invalid funding input");
    seen.add(hex(point));
  }
  const data = dynamic(fields[5]!, 64).map(byteVector);
  const outputCells = dynamic(fields[4]!, 64);
  requireValue(outputCells.length > 0 && outputCells.length === data.length, "invalid root output count");
  const outputs = outputCells.map((cell, i) => {
    const [capacityBytes, lock, typeBytes] = table(cell, 3);
    requireValue(capacityBytes!.length === 8, "invalid output capacity encoding");
    scriptOccupied(lock!);
    const type = typeBytes!.length === 0 ? undefined : typeBytes!;
    if (type !== undefined) scriptOccupied(type);
    const capacity = unsigned(capacityBytes!, 0, 8);
    requireValue(capacity >= (8n + scriptOccupied(lock!) + (type === undefined ? 0n : scriptOccupied(type)) + BigInt(data[i]!.length)) * 100_000_000n,
      "root output below occupied capacity");
    return {capacity, lock: lock!, type, data: data[i]!};
  });
  requireValue(outputs.reduce((sum, output) => sum + output.capacity, 0n) <= MAX_U64, "root output capacity overflow");
  const witnesses = dynamic(witnessVector!, MAX_FUNDING_BYTES / 8).map(byteVector);
  requireValue(emptyMorphWitness || witnesses.length > 0, "missing transaction witness zero");
  const witnessFields = emptyMorphWitness && (witnesses[0]?.length ?? 0) === 0
    ? [new Uint8Array(), new Uint8Array(), new Uint8Array()] : table(witnesses[0]!, 3);
  return {raw: body!, fields, witnesses, witnessFields, inputs, outputs, dependencies};
}
function validPublicKey(key: Uint8Array): boolean {
  if (key.length !== 33) return false;
  try { secp256k1.Point.fromBytes(key); return true; } catch { return false; }
}
function emptySignatureWitness(participants: [string, string]): Uint8Array {
  const keys = participants.map((key) => bytes(key, 33));
  requireValue(keys.every(validPublicKey) && participants[0] < participants[1], "invalid or unordered root participants");
  return join(Uint8Array.of(1, 0, 2, 2), keys[0]!, new Uint8Array(64), keys[1]!, new Uint8Array(64));
}
function initialRecovery(value: MultiAssetRecoveryPackage, creation: PackageEvidence, points: Uint8Array[]): MultiAssetRecoveryPackage {
  const header = creation.header.slice(); const parts = recoveryParts(creation.witness);
  header.set(little(1, 8), 108); header[117] = 2;
  header.set(domainHash("CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1", header.slice(250, 282), little(points.length, 2), ...points), 282);
  const prefix = creation.witness.slice(0, 28); prefix.set(little(points.length, 2), 20);
  return {...value, header_hex: hex(header), witness_hex: hex(join(prefix, parts.manifest, parts.descriptor, ...points,
    ...parts.scripts.map(script => join(little(script.length, 4), script))))};
}
interface RootEvidence { inspection: MultiAssetRootInspection; creation: PackageEvidence; exit: MultiAssetRecoveryPackage; tx: TransactionEvidence }
function rootEvidence(draft: MultiAssetRootDraft): RootEvidence {
  requireValue(typeof draft === "object" && draft !== null && draft.schema === "morph.multi_asset_root_draft.v1"
    && Object.keys(draft).sort().join(",") === "participants,schema,transaction_hex"
    && Array.isArray(draft.participants) && draft.participants.length === 2, "unsupported root draft fields");
  const tx = transactionEvidence(bytes(draft.transaction_hex, MAX_FUNDING_BYTES));
  requireValue(tx.witnessFields[0]!.length === 0 && tx.witnessFields[1]!.length === 0, "root draft contains creation or wallet authorization");
  requireValue(tx.witnessFields[2]!.length > 0, "missing root creation evidence");
  const evidence = byteVector(tx.witnessFields[2]!);
  const scripts = recoveryParts(evidence).scripts;
  requireValue(scripts.length >= 6, "missing root authority Scripts");
  const states = tx.outputs.map((output, index) => ({output, index})).filter(({output}) => output.type !== undefined && same(output.type, scripts[4]!));
  requireValue(states.length === 1, "root requires exactly one authentic State output");
  const {output: state, index: stateIndex} = states[0]!;
  requireValue(same(state.lock, scripts[5]!), "root State lock mismatch");
  const header = state.data;
  requireValue(header.length === 318 && unsigned(header, 68, 8) === 0n && unsigned(header, 108, 8) === 0n
    && header[117] === 1 && zero(header.slice(282, 314)), "root creation must be unbound epoch-0 Active/0");
  requireValue(same(hash(tx.inputs[0]!, little(stateIndex, 8)), header.slice(76, 108)), "root anchor does not derive from actual first input and State index");
  const packageValue: MultiAssetRecoveryPackage = {schema: "morph.multi_asset_recovery_package.v1", header_hex: hex(header), witness_hex: hex(evidence),
    signature_witness_hex: hex(emptySignatureWitness(draft.participants)), state_carrier_capacity: state.capacity.toString(), cell_deps: tx.dependencies};
  const creation = inspectEvidence(packageValue, false);
  requireValue(creation.scripts[4]!.length===93, "direct root funding cannot use a Factory-origin State Type");
  const txHash = hash(tx.raw);
  const outpoints = creation.vaults.map((vault) => {
    const matches = tx.outputs.map((output, index) => ({output, index})).filter(({output}) => same(output.lock, scripts[3]!)
      && (vault.asset.kind === 0 ? output.type === undefined : output.type !== undefined && same(hash(output.type), vault.asset.type)));
    requireValue(matches.length === 1, "missing or duplicate root Vault");
    const {output, index} = matches[0]!;
    requireValue(output.capacity === vault.value.capacity && same(output.data, vault.asset.kind === 0 ? new Uint8Array() : little(vault.value.amount, 16)), "root Vault physical value mismatch");
    return {tx_hash: hex(txHash), index};
  });
  const selected = new Set(outpoints.map((point) => point.index));
  tx.outputs.forEach((output, index) => {
    requireValue(!same(output.lock, scripts[3]!) || selected.has(index), "unlisted root Vault");
    requireValue(!same(output.lock, scripts[5]!) || index === stateIndex, "unlisted root StateLock");
  });
  const exit = initialRecovery(packageValue, creation, outpoints.map(point => join(txHash, little(point.index, 4))));
  const next = inspectEvidence(exit, false);
  const inspection: MultiAssetRootInspection = {transaction_hash: hex(txHash), chain_id: hex(header.slice(2, 34)), channel_id: next.summary.channel_id,
    funding_context_id: next.summary.funding_context_id, creation_digest: hex(domainHash("CKB_MORPH_MULTI_ASSET_ROOT_FUNDING_V1", bytes(creation.summary.package_id, 32), txHash)),
    exit_digest: next.summary.package_id, state_carrier_capacity: state.capacity.toString(), participants: [...draft.participants],
    participant_lock_hashes: [hex(creation.descriptor.slice(4, 36)), hex(creation.descriptor.slice(36, 68))], vault_outpoints: outpoints,
    assets: next.summary.assets, payouts: creation.vaults.map((vault, i) => ({type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type),
      allocations: creation.payouts[i]!.map((value) => ({reserve: value.reserve.toString(), business_ckb: value.business.toString(), amount: value.amount.toString()})) as MultiAssetProposalInspection["payouts"][number]["allocations"]})),
    input_count: tx.inputs.length, output_count: tx.outputs.length};
  return {inspection, creation, exit, tx};
}
/** Inspect unsigned funding and its exact initial exit. This stateless operation
 * does not reserve either signing role or establish chain/code approval. */
export function inspectMultiAssetRootDraft(draft: MultiAssetRootDraft): MultiAssetRootInspection { return rootEvidence(draft).inspection; }

function fundingReceipt(draft: MultiAssetRootDraft, target: MultiAssetFundingTarget, receipt: MultiAssetSignatureReceipt): {signer_pubkey: string; signing_digest: string} {
  requireValue(target === "exit" || target === "creation", "unknown funding signing target");
  const root = rootEvidence(draft).inspection;
  const digest = target === "exit" ? root.exit_digest : root.creation_digest;
  return verifyReceipt(digest, root.participants, receipt);
}
function verifyReceipt(digest: string, participants: readonly string[], receipt: MultiAssetSignatureReceipt): {signer_pubkey: string; signing_digest: string} {
  requireValue(typeof receipt === "object" && receipt !== null && receipt.schema === "morph.multi_asset_signature.v1"
    && Object.keys(receipt).sort().join(",") === "pubkey,schema,signature,signing_digest"
    && receipt.signing_digest === digest && participants.includes(receipt.pubkey), "receipt context or signer mismatch");
  requireValue(secp256k1.verify(bytes(receipt.signature, 64), bytes(digest, 32), bytes(receipt.pubkey, 33), {prehash: false, lowS: true, format: "compact"}), "invalid receipt signature");
  return {signer_pubkey: receipt.pubkey, signing_digest: digest};
}
export function inspectMultiAssetFundingSignature(draft: MultiAssetRootDraft, target: MultiAssetFundingTarget, receipt: MultiAssetSignatureReceipt): {signer_pubkey: string; signing_digest: string} {
  return fundingReceipt(draft, target, receipt);
}
function receiptPair(digest: string, participants: readonly string[], receipts: MultiAssetSignatureReceipt[]): Uint8Array {
  requireValue(Array.isArray(receipts) && receipts.length === 2, "requires both participant receipts");
  receipts.forEach((receipt) => verifyReceipt(digest, participants, receipt));
  const sorted = [...receipts].sort((a, b) => a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0);
  requireValue(sorted[0]!.pubkey !== sorted[1]!.pubkey, "duplicate participant receipt");
  return join(Uint8Array.of(1, 0, 2, 2), ...sorted.map((receipt) => join(bytes(receipt.pubkey, 33), bytes(receipt.signature, 64))));
}
/** Collect public receipts after each participant used its own durable journal.
 * Persist the returned complete exit before exposing/submitting the transaction. */
export function assembleMultiAssetRootFunding(draft: MultiAssetRootDraft, exitReceipts: MultiAssetSignatureReceipt[], creationReceipts: MultiAssetSignatureReceipt[]): MultiAssetRootFunding {
  const root = rootEvidence(draft);
  const exitSignatures = receiptPair(root.inspection.exit_digest, root.inspection.participants, exitReceipts);
  const recovery = {...root.exit, signature_witness_hex: hex(exitSignatures)};
  inspectMultiAssetPackage(recovery);
  const creationSignatures = receiptPair(root.inspection.creation_digest, root.inspection.participants, creationReceipts);
  const witnesses = root.tx.witnesses.slice();
  witnesses[0] = encodeTable([root.tx.witnessFields[0]!, encodeBytes(creationSignatures), root.tx.witnessFields[2]!]);
  const transaction = encodeTable([root.tx.raw, encodeDynamic(witnesses.map(encodeBytes))]);
  requireValue(transaction.length <= MAX_FUNDING_BYTES, "signed root funding exceeds byte limit");
  return {schema: "morph.multi_asset_root_funding.v1", transaction_hex: hex(transaction), recovery_package: recovery};
}
/** Verify signed root creation against the exact raw body and a complete,
 * possibly newer exit. Wallet signatures and canonical custody require RPC. */
export function inspectMultiAssetRootFunding(value: MultiAssetRootFunding): MultiAssetRootInspection {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.multi_asset_root_funding.v1"
    && Object.keys(value).sort().join(",") === "recovery_package,schema,transaction_hex", "unsupported root funding fields");
  const summary = inspectMultiAssetPackage(value.recovery_package);
  const tx = transactionEvidence(bytes(value.transaction_hex, MAX_FUNDING_BYTES));
  requireValue(tx.witnessFields[1]!.length > 0, "missing root creation signatures");
  const signatures = byteVector(tx.witnessFields[1]!);
  requireValue(signatures.length === 198 && u16(signatures, 0) === 1 && signatures[2] === 2 && signatures[3] === 2, "invalid root creation signature envelope");
  const participants: [string, string] = [hex(signatures.slice(4, 37)), hex(signatures.slice(101, 134))];
  const witnesses = tx.witnesses.slice(); witnesses[0] = encodeTable([new Uint8Array(), new Uint8Array(), tx.witnessFields[2]!]);
  const draft: MultiAssetRootDraft = {schema: "morph.multi_asset_root_draft.v1", transaction_hex: hex(encodeTable([tx.raw, encodeDynamic(witnesses.map(encodeBytes))])), participants};
  const root = rootEvidence(draft);
  for (let i = 0; i < 2; i++) {
    fundingReceipt(draft, "creation", {schema: "morph.multi_asset_signature.v1", signing_digest: root.inspection.creation_digest,
      pubkey: participants[i]!, signature: hex(signatures.slice(37 + 97 * i, 101 + 97 * i))});
  }
  const current = inspectEvidence(value.recovery_package, true);
  const initial = bytes(root.exit.header_hex, 318);
  requireValue(summary.phase === "settling" && summary.vaults_bound && same(current.header.slice(0, 108), initial.slice(0, 108))
    && current.header[116] === initial[116] && same(current.header.slice(118, 182), initial.slice(118, 182))
    && same(current.header.slice(214), initial.slice(214)), "root recovery funding context mismatch");
  requireValue(current.scripts.length === root.creation.scripts.length && current.scripts.every((script, i) => same(script, root.creation.scripts[i]!)), "root recovery Scripts differ from creation");
  const currentParts = recoveryParts(current.witness); const initialParts = recoveryParts(bytes(root.exit.witness_hex, MAX_WITNESS_BYTES));
  requireValue(same(currentParts.manifest, initialParts.manifest) && same(currentParts.points, initialParts.points), "root recovery custody differs from creation");
  return root.inspection;
}

export interface MultiAssetRootCollection {
  schema: "morph.multi_asset_root_collection.v1";
  draft: MultiAssetRootDraft;
  exit_signatures: MultiAssetSignatureReceipt[];
  creation_signatures: MultiAssetSignatureReceipt[];
}
export interface MultiAssetRootCollectionSummary extends MultiAssetRootInspection {
  exit_signature_count: number;
  creation_signature_count: number;
  ready_to_export: boolean;
}
/** Public coordination evidence, without signer keys or rollback authority. */
export function inspectMultiAssetRootCollection(value: MultiAssetRootCollection): MultiAssetRootCollectionSummary {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.multi_asset_root_collection.v1"
    && Object.keys(value).sort().join(",") === "creation_signatures,draft,exit_signatures,schema", "unsupported root collection fields");
  const root = inspectMultiAssetRootDraft(value.draft);
  for (const [target, receipts] of [["exit", value.exit_signatures], ["creation", value.creation_signatures]] as const) {
    requireValue(Array.isArray(receipts) && receipts.length <= 2, "too many root collection receipts");
    let previous: string | undefined;
    for (const receipt of receipts) {
      inspectMultiAssetFundingSignature(value.draft, target, receipt);
      requireValue(previous === undefined || previous < receipt.pubkey, "root collection receipts must be unique and ordered");
      previous = receipt.pubkey;
    }
  }
  requireValue(value.creation_signatures.length === 0 || value.exit_signatures.length === 2, "creation collection requires complete initial exit");
  return {...root, exit_signature_count: value.exit_signatures.length, creation_signature_count: value.creation_signatures.length,
    ready_to_export: value.exit_signatures.length === 2 && value.creation_signatures.length === 2};
}

export interface MultiAssetSpliceDraft {
  schema: "morph.multi_asset_splice_draft.v1";
  base_state_digest: string;
  transaction_hex: string;
  new_witness_hex: string;
  flows_hex: string;
}
export type MultiAssetSpliceTarget = "splice-creation" | "splice-recovery" | "splice-bridge";
type PublicAllocation = MultiAssetProposalInspection["payouts"][number]["allocations"][number];
export interface MultiAssetSpliceInspection {
  transaction_hash: string;
  channel_id: string;
  old_funding_context_id: string;
  new_funding_context_id: string;
  funding_epoch: string;
  old_state_outpoint: {tx_hash: string; index: number};
  creation_digest: string;
  recovery_digest: string;
  bridge_digest: string;
  withdrawal_lock_hex: string;
  vault_outpoints: Array<{tx_hash: string; index: number}>;
  assets: MultiAssetPackageSummary["assets"];
  payouts: MultiAssetProposalInspection["payouts"];
  flows: Array<{type_hash: string | null; deposit: PublicAllocation; withdrawal: PublicAllocation}>;
}
export interface MultiAssetSpliceFunding {
  schema: "morph.multi_asset_splice_funding.v1";
  transaction_hex: string;
  recovery_package: MultiAssetRecoveryPackage;
}
const publicAllocation = (value: Allocation): PublicAllocation => ({reserve: value.reserve.toString(), business_ckb: value.business.toString(), amount: value.amount.toString()});
interface SpliceEvidence {
  inspection: MultiAssetSpliceInspection;
  tx: TransactionEvidence;
  old: PackageEvidence;
  next: PackageEvidence;
  recovery: MultiAssetRecoveryPackage;
  bridgeHeader: Uint8Array;
  withdrawal: Uint8Array;
  flows: Uint8Array;
}
function spliceEvidence(current: MultiAssetRecoveryPackage, draft: MultiAssetSpliceDraft): SpliceEvidence {
  const old = inspectEvidence(current, true);
  requireValue(typeof draft === "object" && draft !== null && draft.schema === "morph.multi_asset_splice_draft.v1"
    && Object.keys(draft).sort().join(",") === "base_state_digest,flows_hex,new_witness_hex,schema,transaction_hex"
    && draft.base_state_digest === old.summary.package_id && old.summary.vaults_bound, "splice base state mismatch");
  const tx = transactionEvidence(bytes(draft.transaction_hex, MAX_FUNDING_BYTES), true);
  requireValue(tx.inputs.length > old.vaults.length && tx.witnesses.length <= tx.inputs.length
    && (tx.witnesses[0]?.length ?? 0) === 0, "splice draft input count or Morph witness mismatch");
  const oldParts = recoveryParts(old.witness);
  for (let i = 0; i <= old.vaults.length; i++) {
    requireValue(zero(tx.inputs[i]!.slice(0, 8)), "splice protocol input since must be zero");
    if (i > 0) requireValue(same(tx.inputs[i]!.slice(8), oldParts.points.slice((i - 1) * 36, i * 36)), "splice old Vault order mismatch");
  }
  for (const dep of tx.dependencies) requireValue(!tx.inputs.some(input => hex(input.slice(8, 40)) === dep.tx_hash && u32(input, 40) === dep.index), "splice consumes recovery dependency");
  const state = tx.outputs[0]!;
  const nextPackage: MultiAssetRecoveryPackage = {...current, header_hex: hex(state.data), witness_hex: draft.new_witness_hex,
    signature_witness_hex: hex(emptySignatureWitness(old.summary.signer_pubkeys)), cell_deps: tx.dependencies};
  const next = inspectEvidence(nextPackage, false);
  requireValue(!next.summary.vaults_bound && next.summary.phase === "active" && next.summary.state_number === "0"
    && same(old.header.slice(2, 68), next.header.slice(2, 68))
    && unsigned(old.header, 68, 8) + 1n === unsigned(next.header, 68, 8)
    && same(old.header.slice(116, 117), next.header.slice(116, 117))
    && same(old.header.slice(118, 150), next.header.slice(118, 150))
    && same(old.header.slice(216, 248), next.header.slice(216, 248)), "splice changes stable channel identity or epoch");
  requireValue(same(hash(tx.inputs[0]!, little(0, 8)), next.header.slice(76, 108)), "splice anchor mismatch");
  requireValue(state.capacity === BigInt(current.state_carrier_capacity) && state.type !== undefined
    && same(state.type, next.scripts[4]!) && same(state.lock, next.scripts[5]!), "splice State carrier or authority mismatch");
  for (let i = 0; i < 3; i++) requireValue(same(old.scripts[i]!, next.scripts[i]!), "splice changes payout authority");
  for (let i = 3; i < 6; i++) requireValue(same(old.scripts[i]!.slice(0, 49), next.scripts[i]!.slice(0, 49)), "splice changes authority code");
  requireValue(same(old.scripts[3]!.slice(97, 105), next.scripts[3]!.slice(97, 105))
    && same(old.scripts[4]!.slice(85), next.scripts[4]!.slice(85)), "splice changes challenge policy");
  const flows = bytes(draft.flows_hex, 4 + 16 * 97);
  const count = u16(flows, 0);
  requireValue(count > 0 && count <= 16 && u16(flows, 2) === 0 && flows.length === 4 + count * 97, "invalid splice flow table");
  const union = [...new Set([...old.vaults, ...next.vaults].map(vault => vault.asset.key))].sort();
  requireValue(count === union.length, "splice flows must cover exact asset union");
  const values = Array.from({length: count}, (_, i) => {
    const offset = 4 + i * 97; const id = asset(flows, offset);
    requireValue(id.key === union[i], "splice flow asset order mismatch");
    // Deposits are deltas: token-only top-ups need no additional reserve.
    const reserve = unsigned(flows, offset + 33, 8); const business = unsigned(flows, offset + 41, 8);
    const amount = unsigned(flows, offset + 49, 16);
    const deposit: Allocation = {reserve, business, amount, capacity: reserve + business};
    requireValue(deposit.capacity <= MAX_U64 && (id.kind !== 0 || amount === 0n), "invalid splice deposit");
    const withdrawal = allocation(flows, offset + 65, id, false);
    const before = old.vaults.find(vault => vault.asset.key === id.key)?.value;
    const after = next.vaults.find(vault => vault.asset.key === id.key)?.value;
    for (const lane of ["reserve", "business", "amount"] as const) {
      const total = (before?.[lane] ?? 0n) + deposit[lane]; const cap = lane === "amount" ? (1n << 128n) - 1n : MAX_U64;
      requireValue(total <= cap && total === (after?.[lane] ?? 0n) + withdrawal[lane], "splice per-asset conservation mismatch");
    }
    return {id, deposit, withdrawal};
  });
  const withdrawals = values.filter(flow => flow.withdrawal.capacity > 0n);
  const withdrawal = withdrawals.length === 0 ? new Uint8Array() : tx.outputs[1 + next.vaults.length]?.lock;
  requireValue(withdrawal !== undefined, "missing splice withdrawal output");
  const expected = [...next.vaults.map(vault => ({id: vault.asset, value: vault.value, lock: next.scripts[3]!})),
    ...withdrawals.map(flow => ({id: flow.id, value: flow.withdrawal, lock: withdrawal}))];
  requireValue(tx.outputs.length > expected.length, "missing splice value outputs");
  expected.forEach(({id, value, lock}, i) => {
    const output = tx.outputs[i + 1]!;
    const type = value.amount === 0n ? undefined : [...next.scripts.slice(6), ...old.scripts.slice(6)].find(script => same(hash(script), id.type));
    requireValue(value.amount === 0n || type !== undefined, "missing splice Type Script");
    requireValue(same(output.lock, lock) && output.capacity === value.capacity
      && (type === undefined ? output.type === undefined : output.type !== undefined && same(output.type, type))
      && same(output.data, type === undefined ? new Uint8Array() : little(value.amount, 16))
      && value.reserve >= occupied(lock, type), "splice physical output differs from signed allocation");
  });
  tx.outputs.forEach((output, i) => {
    if (i === 0) return;
    requireValue(!same(output.lock, old.scripts[3]!) && (i <= expected.length || !same(output.lock, next.scripts[3]!))
      && (output.type === undefined || (!same(output.type, old.scripts[4]!) && !same(output.type, next.scripts[4]!))), "splice recreates or duplicates custody");
  });
  const txHash = hash(tx.raw); const points = next.vaults.map((_, i) => join(txHash, little(i + 1, 4)));
  const recovery = initialRecovery(nextPackage, next, points);
  const exit = inspectEvidence(recovery, false);
  const bridgeHeader = join(little(1, 2), little(0, 2), bytes(old.summary.funding_context_id, 32), tx.inputs[0]!.slice(8),
    bytes(next.summary.package_id, 32), domainHash("CKB_MORPH_MULTI_ASSET_SPLICE_FLOW_V1", flows), withdrawal.length === 0 ? new Uint8Array(32) : hash(withdrawal), txHash);
  const inspection: MultiAssetSpliceInspection = {transaction_hash: hex(txHash), channel_id: old.summary.channel_id,
    old_funding_context_id: old.summary.funding_context_id, new_funding_context_id: exit.summary.funding_context_id,
    funding_epoch: unsigned(next.header, 68, 8).toString(), old_state_outpoint: {tx_hash: hex(tx.inputs[0]!.slice(8, 40)), index: u32(tx.inputs[0]!, 40)},
    creation_digest: next.summary.package_id, recovery_digest: exit.summary.package_id, bridge_digest: hex(domainHash("CKB_MORPH_MULTI_ASSET_SPLICE_V1", bridgeHeader)),
    withdrawal_lock_hex: hex(withdrawal), vault_outpoints: points.map(point => ({tx_hash: hex(point.slice(0, 32)), index: u32(point, 32)})), assets: next.summary.assets,
    payouts: next.vaults.map((vault, i) => ({type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type), allocations: next.payouts[i]!.map(publicAllocation) as [PublicAllocation, PublicAllocation]})),
    flows: values.map(flow => ({type_hash: flow.id.kind === 0 ? null : hex(flow.id.type), deposit: publicAllocation(flow.deposit), withdrawal: publicAllocation(flow.withdrawal)}))};
  return {inspection, tx, old, next, recovery, bridgeHeader, withdrawal, flows};
}
/** Verify exact unsigned splice terms. RPC custody and durable signer history
 * are separate requirements before authorising or broadcasting the intent. */
export function inspectMultiAssetSpliceDraft(current: MultiAssetRecoveryPackage, draft: MultiAssetSpliceDraft): MultiAssetSpliceInspection {
  return spliceEvidence(current, draft).inspection;
}
function spliceDigest(inspection: MultiAssetSpliceInspection, target: MultiAssetSpliceTarget): string {
  requireValue(["splice-creation", "splice-recovery", "splice-bridge"].includes(target), "unknown splice signing target");
  return target === "splice-creation" ? inspection.creation_digest : target === "splice-recovery" ? inspection.recovery_digest : inspection.bridge_digest;
}
export function inspectMultiAssetSpliceSignature(current: MultiAssetRecoveryPackage, draft: MultiAssetSpliceDraft, target: MultiAssetSpliceTarget, receipt: MultiAssetSignatureReceipt): {signer_pubkey: string; signing_digest: string} {
  const proof = spliceEvidence(current, draft);
  return verifyReceipt(spliceDigest(proof.inspection, target), proof.old.summary.signer_pubkeys, receipt);
}
/** Assemble public authorisations only after the complete future exit has
 * been retained by each participant's authoritative signing journal. */
export function assembleMultiAssetSpliceFunding(current: MultiAssetRecoveryPackage, draft: MultiAssetSpliceDraft, recoveryReceipts: MultiAssetSignatureReceipt[], creationReceipts: MultiAssetSignatureReceipt[], bridgeReceipts: MultiAssetSignatureReceipt[]): MultiAssetSpliceFunding {
  const proof = spliceEvidence(current, draft); const info = proof.inspection; const keys = proof.old.summary.signer_pubkeys;
  const recovery = {...proof.recovery, signature_witness_hex: hex(receiptPair(info.recovery_digest, keys, recoveryReceipts))};
  inspectMultiAssetPackage(recovery);
  const creation = receiptPair(info.creation_digest, keys, creationReceipts);
  const bridge = receiptPair(info.bridge_digest, keys, bridgeReceipts);
  const oldParts = recoveryParts(proof.old.witness);
  const prefix = join(utf8.encode("MORPHMS!"), little(1, 2), little(0, 2), little(oldParts.manifest.length, 4), little(oldParts.pointCount, 2), little(0, 2),
    little(proof.next.witness.length, 4), little(proof.withdrawal.length, 4), little(proof.flows.length, 4));
  const envelope = join(prefix, proof.bridgeHeader, proof.next.header, bridge, oldParts.manifest, oldParts.points, proof.next.witness, proof.withdrawal, proof.flows);
  const witnesses = proof.tx.witnesses.slice(); witnesses[0] = encodeTable([new Uint8Array(), encodeBytes(creation), encodeBytes(envelope)]);
  const transaction = encodeTable([proof.tx.raw, encodeDynamic(witnesses.map(encodeBytes))]);
  requireValue(transaction.length <= MAX_FUNDING_BYTES, "signed splice transaction exceeds byte limit");
  return {schema: "morph.multi_asset_splice_funding.v1", transaction_hex: hex(transaction), recovery_package: recovery};
}

/** Independently verify a completed splice export, including its exact initial
 * exit, both creation signatures and both old-context bridge signatures. */
export function inspectMultiAssetSpliceFunding(current: MultiAssetRecoveryPackage, value: MultiAssetSpliceFunding): MultiAssetSpliceInspection {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.multi_asset_splice_funding.v1"
    && Object.keys(value).sort().join(",") === "recovery_package,schema,transaction_hex", "unsupported splice export fields");
  const tx = transactionEvidence(bytes(value.transaction_hex, MAX_FUNDING_BYTES));
  requireValue(tx.witnessFields[0]!.length === 0 && tx.witnessFields[1]!.length > 0 && tx.witnessFields[2]!.length > 0, "missing splice authorisations");
  const envelope = byteVector(tx.witnessFields[2]!);
  requireValue(envelope.length >= 748 && same(envelope.slice(0, 8), utf8.encode("MORPHMS!"))
    && u16(envelope, 8) === 1 && u16(envelope, 10) === 0 && u16(envelope, 18) === 0, "invalid splice envelope");
  const oldManifestLength = u32(envelope, 12); const oldPointCount = u16(envelope, 16);
  const evidenceLength = u32(envelope, 20); const withdrawalLength = u32(envelope, 24); const flowsLength = u32(envelope, 28);
  const evidenceStart = 748 + oldManifestLength + 36 * oldPointCount; const flowsStart = evidenceStart + evidenceLength + withdrawalLength;
  requireValue(oldManifestLength <= 4 + 8 * 97 && oldPointCount <= 8 && evidenceLength <= MAX_WITNESS_BYTES
    && withdrawalLength <= MAX_SCRIPT_BYTES && flowsLength <= 4 + 16 * 97 && flowsStart + flowsLength === envelope.length, "splice envelope component bounds");
  const witnesses = tx.witnesses.slice(); witnesses[0] = new Uint8Array();
  const draft: MultiAssetSpliceDraft = {schema: "morph.multi_asset_splice_draft.v1", base_state_digest: inspectMultiAssetPackage(current).package_id,
    transaction_hex: hex(encodeTable([tx.raw, encodeDynamic(witnesses.map(encodeBytes))])),
    new_witness_hex: hex(envelope.slice(evidenceStart, evidenceStart + evidenceLength)), flows_hex: hex(envelope.slice(flowsStart))};
  const info = inspectMultiAssetSpliceDraft(current, draft);
  const receipts = (raw: Uint8Array, digest: string): MultiAssetSignatureReceipt[] => {
    requireValue(raw.length === 198 && u16(raw, 0) === 1 && raw[2] === 2 && raw[3] === 2, "invalid splice signature envelope");
    return [0, 1].map(i => ({schema: "morph.multi_asset_signature.v1", signing_digest: digest,
      pubkey: hex(raw.slice(4 + 97 * i, 37 + 97 * i)), signature: hex(raw.slice(37 + 97 * i, 101 + 97 * i))}));
  };
  const expected = assembleMultiAssetSpliceFunding(current, draft,
    receipts(bytes(value.recovery_package.signature_witness_hex, 198), info.recovery_digest),
    receipts(byteVector(tx.witnessFields[1]!), info.creation_digest), receipts(envelope.slice(550, 748), info.bridge_digest));
  requireValue(expected.transaction_hex === value.transaction_hex
    && expected.recovery_package.header_hex === value.recovery_package.header_hex
    && expected.recovery_package.witness_hex === value.recovery_package.witness_hex
    && expected.recovery_package.signature_witness_hex === value.recovery_package.signature_witness_hex
    && expected.recovery_package.state_carrier_capacity === value.recovery_package.state_carrier_capacity
    && Array.isArray(value.recovery_package.cell_deps) && expected.recovery_package.cell_deps.length === value.recovery_package.cell_deps.length
    && expected.recovery_package.cell_deps.every((dep, i) => dep.tx_hash === value.recovery_package.cell_deps[i]!.tx_hash
      && dep.index === value.recovery_package.cell_deps[i]!.index && dep.dep_type === value.recovery_package.cell_deps[i]!.dep_type), "splice export differs from canonical signed intent");
  inspectMultiAssetPackage(value.recovery_package);
  return info;
}
