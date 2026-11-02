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

/** Verify both signatures, all commitments, provenance, per-asset conservation,
 * and occupied-capacity funding without converting u64/u128 values to Number.
 * Chain liveness, confirmations, and deployed code approval require an RPC and
 * the operator's release policy in addition to this local evidence check. */
export function inspectMultiAssetPackage(value: MultiAssetRecoveryPackage): MultiAssetPackageSummary {
  return inspectPackage(value, true);
}

function inspectPackage(value: MultiAssetRecoveryPackage, verifySignatures: boolean): MultiAssetPackageSummary {
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
  const count = u16(header, 314);
  const contentRoot = header.slice(250, 282);
  const pointRoot = header.slice(282, 314);
  const bound = !zero(pointRoot);
  requireValue(!verifySignatures || bound || u64(header, 68) !== 0n,
    "root creation requires transaction-bound funding authorization");
  requireValue(count >= 1 && count <= MAX_VAULTS && !zero(contentRoot)
    && (header[117] !== 2 || bound), "invalid Vault context");
  const witness = bytes(value.witness_hex, MAX_WITNESS_BYTES);
  requireValue(witness.length >= 28 && same(witness.slice(0, 8), utf8.encode("MORPHMA!"))
    && u16(witness, 8) === 1 && u16(witness, 10) === 0 && u16(witness, 22) === 0, "invalid recovery witness");
  const manifestEnd = 28 + u32(witness, 12);
  const descriptorEnd = manifestEnd + u32(witness, 16);
  const pointCount = u16(witness, 20);
  const scriptsStart = descriptorEnd + 36 * pointCount;
  requireValue(pointCount <= MAX_VAULTS && scriptsStart + u32(witness, 24) === witness.length, "truncated recovery evidence");
  const manifest = witness.slice(28, manifestEnd);
  const descriptor = witness.slice(manifestEnd, descriptorEnd);
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
  const points = witness.slice(descriptorEnd, scriptsStart);
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
  const scripts: Uint8Array[] = [];
  let cursor = scriptsStart;
  for (let i = 0; i < 6 + typed.length; i++) {
    const len = u32(witness, cursor);
    requireValue(len >= 53 && len <= MAX_SCRIPT_BYTES && cursor + 4 + len <= witness.length, "invalid script evidence length");
    const script = witness.slice(cursor + 4, cursor + 4 + len);
    scriptOccupied(script);
    scripts.push(script);
    cursor += 4 + len;
  }
  requireValue(cursor === witness.length, "extra script evidence");
  for (let i = 0; i < 3; i++) requireValue(same(hash(scripts[i]!), locks[i]!), "payout script identity mismatch");
  const vaultScript = scripts[3]!;
  const stateType = scripts[4]!;
  const stateLock = scripts[5]!;
  const vaultArgs = vaultScript.slice(53);
  requireValue(vaultArgs.length === 116 && same(vaultArgs.slice(0, 8), utf8.encode("MORPHMV!"))
    && u16(vaultArgs, 8) === 1 && u16(vaultArgs, 10) === 0
    && !zero(vaultArgs.slice(12, 44)) && (unsigned(vaultArgs, 44, 8) >> 56n) === 0x80n
    && same(vaultArgs.slice(52, 84), hash(stateType)) && same(vaultArgs.slice(84, 116), hash(stateLock))
    && stateType.length === 93 && same(stateType.slice(53, 85), vaultArgs.slice(12, 44))
    && same(stateType.slice(85), vaultArgs.slice(44, 52)) && same(stateLock.slice(53), hash(stateType))
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
  return {
    package_id: hex(digest), channel_id: hex(header.slice(36, 68)),
    funding_context_id: hex(domainHash("CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1", header.slice(2, 34), header.slice(36, 68), header.slice(76, 108), contentRoot, pointRoot)),
    state_number: unsigned(header, 108, 8).toString(), phase: header[117] === 1 ? "active" : "settling",
    vaults_bound: bound, vault_count: count, witness_bytes: witness.length,
    dependency_count: value.cell_deps.length,
    state_carrier_capacity: value.state_carrier_capacity, signer_pubkeys: [hex(publicKeys[0]), hex(publicKeys[1])],
    assets: vaults.map((vault) => ({ type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type), reserve: vault.value.reserve.toString(), business_ckb: vault.value.business.toString(), amount: vault.value.amount.toString() })),
  };
}


export interface MultiAssetProposal {
  schema: "morph.multi_asset_proposal.v1";
  base_state_digest: string;
  state_number: string;
  descriptor_hex: string;
  signing_digest: string;
}

export interface MultiAssetProposalSignature {
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

export function inspectMultiAssetProposalSignature(base: MultiAssetRecoveryPackage, proposal: MultiAssetProposal, signature: MultiAssetProposalSignature): { signer_pubkey: string; signing_digest: string } {
  const inspected = inspectMultiAssetProposal(base, proposal);
  requireValue(typeof signature === "object" && signature !== null && signature.schema === "morph.multi_asset_signature.v1"
    && Object.keys(signature).sort().join(",") === "pubkey,schema,signature,signing_digest", "unsupported proposal signature fields");
  requireValue(signature.signing_digest === proposal.signing_digest
    && inspected.summary.signer_pubkeys.includes(signature.pubkey), "proposal signature context or signer mismatch");
  const raw = bytes(signature.signature, 64);
  requireValue(raw.length === 64 && secp256k1.verify(raw, bytes(proposal.signing_digest, 32), bytes(signature.pubkey, 33), {
    prehash: false, lowS: true, format: "compact",
  }), "invalid proposal signature");
  return { signer_pubkey: signature.pubkey, signing_digest: signature.signing_digest };
}
