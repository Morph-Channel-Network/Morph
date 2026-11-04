import { MAX_U64, MAX_SCRIPT_BYTES, utf8, requireValue, bytes, hex, join, hash, domainHash, same, zero, unsigned, u16, u32, little, asset, allocation, scriptOccupied, occupied, byteVector, encodeTable, encodeDynamic, encodeBytes, transactionEvidence, validPublicKey, type Vault, type Allocation, type TransactionEvidence } from "./protocol-wire.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

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
  capability: MultiAssetSettlementCapabilityInspection;
  assets: Array<{ type_hash: string | null; reserve: string; business_ckb: string; amount: string }>;
}

const MAX_VAULTS = 8;
const BATCH_DESCRIPTOR_BYTES = 156 + 8 * 84;
const CONDITIONAL_BYTES = 36 + BATCH_DESCRIPTOR_BYTES;
const MAX_DESCRIPTOR_BYTES = 100 + MAX_VAULTS * 97 + CONDITIONAL_BYTES;
const MAX_WITNESS_BYTES = 28 + 4 + 8 * 97 + MAX_DESCRIPTOR_BYTES + 8 * 36 + 14 * 516;

function fundingContext(header: Uint8Array): Uint8Array {
  return domainHash("CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1",header.slice(2,34),header.slice(36,68),
    header.slice(76,108),header.slice(250,282),header.slice(282,314));
}

export type MultiAssetSettlementCapabilityInspection = { kind: "ordinary" } | {
  kind: "ckb_conditional";
  batch_code_hash: string;
  batch_hash_type: number;
  batch_id: string;
  application_context_commitment: string;
  pending_ckb: string;
  batch_lock_hash: string;
  settled_capacities: [string, string];
  transfers: Array<{
    transfer_id: string;
    payer_lock_hash: string;
    payee_lock_hash: string;
    hash_algorithm: "ckb_blake2b" | "sha256";
    payment_hash: string;
    amount: string;
    refund_after_block: string;
  }>;
};

interface SettlementCapability {
  inspection: MultiAssetSettlementCapabilityInspection;
  pending: bigint;
  settled: readonly [bigint, bigint] | undefined;
  batchScript: Uint8Array | undefined;
}

function settlementCapability(descriptor: Uint8Array, count: number, header: Uint8Array): SettlementCapability {
  const prefix = 100 + count * 97;
  const tag = descriptor[3];
  requireValue(tag === 0 || tag === 1, "unknown settlement capability");
  requireValue(descriptor.length === prefix + (tag === 1 ? CONDITIONAL_BYTES : 0), "invalid settlement descriptor length");
  if (tag === 0) return { inspection: {kind: "ordinary"}, pending: 0n, settled: undefined, batchScript: undefined };
  const conditional = descriptor.slice(prefix);
  requireValue(u16(conditional, 0) === 1 && conditional[2] === 0 && [0,1,2,4].includes(conditional[3]!)
    && !zero(conditional.slice(4,36)), "invalid conditional capability identity");
  const batch = conditional.slice(36);
  const transferCount = batch[68]!;
  requireValue(u16(batch,0) === 3 && batch[2] === 2 && batch[3] === 8 && transferCount >= 1 && transferCount <= 8
    && !zero(batch.slice(4,36)) && !zero(batch.slice(36,68)) && zero(batch.slice(69,76)), "invalid conditional Batch descriptor");
  const locks = [descriptor.slice(4,36), descriptor.slice(36,68)];
  requireValue(same(batch.slice(76,108), locks[0]!) && same(batch.slice(116,148), locks[1]!), "conditional participant mismatch");
  const settled = [unsigned(batch,108,8),unsigned(batch,148,8)] as const;
  requireValue(settled[0] > 0n && settled[1] > 0n, "invalid conditional settled capacities");
  const transfers: Extract<MultiAssetSettlementCapabilityInspection, {kind: "ckb_conditional"}>["transfers"] = [];
  const hashes = new Set<string>();
  let previousId = "";
  let pending = 0n;
  for (let index=0;index<8;index++) {
    const transfer = batch.slice(156+index*84,156+(index+1)*84);
    if (index >= transferCount) {
      requireValue(zero(transfer), "nonzero unused conditional transfer");
      continue;
    }
    const id = hex(transfer.slice(0,32));
    const payer = transfer[32]!;
    const algorithm = transfer[33]!;
    const payment = hex(transfer.slice(36,68));
    const amount = unsigned(transfer,68,8);
    const refund = unsigned(transfer,76,8);
    requireValue(!zero(transfer.slice(0,32)) && id > previousId && payer <= 1 && (algorithm === 0 || algorithm === 1)
      && u16(transfer,34) === 0 && !zero(transfer.slice(36,68)) && !hashes.has(payment)
      && amount > 0n && refund > 0n && refund <= 0x00ff_ffff_ffff_ffffn, "invalid conditional transfer");
    pending += amount;
    requireValue(pending + settled[0] + settled[1] <= MAX_U64, "conditional capacity overflow");
    previousId = id;
    hashes.add(payment);
    transfers.push({transfer_id:id,payer_lock_hash:hex(locks[payer]!),payee_lock_hash:hex(locks[1-payer]!),
      hash_algorithm:algorithm === 0 ? "ckb_blake2b" : "sha256",payment_hash:payment,
      amount:amount.toString(),refund_after_block:refund.toString()});
  }
  requireValue(!zero(header.slice(36,68)), "invalid conditional channel identity");
  const args = join(header.slice(36,68),fundingContext(header),header.slice(108,116),domainHash("CKB_MORPH_SETTLEMENT_DESCRIPTOR",batch));
  const batchScript = encodeTable([conditional.slice(4,36),Uint8Array.of(conditional[3]!),encodeBytes(args)]);
  return {pending,settled,batchScript,inspection:{kind:"ckb_conditional",batch_code_hash:hex(conditional.slice(4,36)),batch_hash_type:conditional[3]!,
    batch_id:hex(batch.slice(4,36)),application_context_commitment:hex(batch.slice(36,68)),pending_ckb:pending.toString(),
    batch_lock_hash:hex(hash(batchScript)),settled_capacities:[settled[0].toString(),settled[1].toString()],transfers}};
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
  capability: SettlementCapability;
}
function inspectPackage(value: MultiAssetRecoveryPackage, verifySignatures: boolean): MultiAssetPackageSummary {
  return inspectEvidence(value, verifySignatures).summary;
}

function inspectEvidence(value: MultiAssetRecoveryPackage, verifySignatures: boolean, dependenciesRequired = true): PackageEvidence {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.multi_asset_recovery_package.v1", "unsupported schema");
  requireValue(Object.keys(value).sort().join(",") === "cell_deps,header_hex,schema,signature_witness_hex,state_carrier_capacity,witness_hex", "unknown package fields");
  requireValue(Array.isArray(value.cell_deps) && value.cell_deps.length >= (dependenciesRequired ? 1 : 0) && value.cell_deps.length <= 64, "incomplete code dependencies");
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
    && header[116] === 1 && [1, 2].includes(header[117]!) && u16(header, 214) === 5
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
  requireValue(descriptor.length >= 100 + count * 97 && u16(descriptor, 0) === 5 && descriptor[2] === count, "invalid settlement descriptor");
  const capability = settlementCapability(descriptor, count, header);
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
    requireValue(a.reserve + b.reserve === funded.reserve && a.business + b.business + (id.kind === 0 ? capability.pending : 0n) === funded.business
      && a.amount + b.amount === funded.amount, "per-asset conservation mismatch");
    payouts.push([a, b]);
  }
  if (capability.settled !== undefined) requireValue(vaults[0]!.asset.kind === 0
    && capability.settled[0] === payouts[0]![0].capacity && capability.settled[1] === payouts[0]![1].capacity,
    "conditional settled allocation mismatch");
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
  if (capability.batchScript !== undefined) {
    const batchHash = hash(capability.batchScript);
    requireValue(occupied(capability.batchScript) <= vaults[0]!.value.reserve, "insufficient conditional Batch reserve");
    requireValue(!same(batchHash,vaultHash) && !same(batchHash,hash(stateLock)) && locks.every(lock => !same(batchHash,lock)),
      "conditional Batch retains payout or channel authority");
  }
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
    funding_context_id: hex(fundingContext(header)),
    state_number: unsigned(header, 108, 8).toString(), phase: header[117] === 1 ? "active" : "settling",
    vaults_bound: bound, vault_count: count, witness_bytes: witness.length,
    dependency_count: value.cell_deps.length,
    state_carrier_capacity: value.state_carrier_capacity, signer_pubkeys: [hex(publicKeys[0]), hex(publicKeys[1])],
    capability: capability.inspection,
    assets: vaults.map((vault) => ({ type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type), reserve: vault.value.reserve.toString(), business_ckb: vault.value.business.toString(), amount: vault.value.amount.toString() })),
  };
  return {summary, header, witness, descriptor, scripts, vaults, payouts, publicKeys, capability};
}

/** Inspect only a Factory child's public initial-exit terms. This accepts no
 * authorization signatures and grants no ability to publish or sign. */
export function inspectMultiAssetPublicExitTerms(headerHex:string,witnessHex:string,carrier:string,participants:[string,string]):MultiAssetPackageSummary {
  const summary=inspectEvidence({schema:"morph.multi_asset_recovery_package.v1",header_hex:headerHex,witness_hex:witnessHex,
    signature_witness_hex:hex(emptySignatureWitness(participants)),state_carrier_capacity:carrier,cell_deps:[]},false,false).summary;
  requireValue(summary.vaults_bound && summary.phase === "settling" && summary.state_number === "1", "child requires bound initial exit terms");
  return summary;
}

/** Review the signed execution capability, including every pending transfer.
 * This performs the same complete package verification as ordinary inspection. */
export function inspectMultiAssetSettlementCapability(value: MultiAssetRecoveryPackage): MultiAssetSettlementCapabilityInspection {
  return inspectEvidence(value, true).capability.inspection;
}

export type ConditionalResolution =
  | { kind: "fulfill"; transfer_id: string; preimage: string }
  | { kind: "refund"; transfer_id: string };

export interface ConditionalBatchPackage {
  schema: "morph.conditional_batch_package.v1";
  source_package: MultiAssetRecoveryPackage;
  resolutions: ConditionalResolution[];
  input_since: string;
  resolution_witness_hex: string;
  resolved_capacities: [string, string];
}

export interface ConditionalBatchPackageInspection {
  schema: "morph.conditional_batch_package.v1";
  source: MultiAssetPackageSummary;
  batch_id: string;
  batch_lock_hash: string;
  transfer_count: number;
  total_capacity: string;
  descriptor_commitment: string;
  input_since: string;
  resolved_capacities: [string, string];
}

function canonicalU64(value: string, label: string): bigint {
  requireValue(typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value), `noncanonical ${label}`);
  const number = BigInt(value);
  requireValue(number <= MAX_U64, `${label} exceeds u64`);
  return number;
}

function conditionalResolutionEvidence(source: MultiAssetRecoveryPackage, resolutions: ConditionalResolution[], since: string): {
  inspection: ConditionalBatchPackageInspection; witness: Uint8Array;
} {
  const evidence = inspectEvidence(source,true);
  const capability = evidence.capability.inspection;
  requireValue(evidence.summary.vaults_bound && evidence.summary.phase === "settling"
    && capability.kind === "ckb_conditional", "conditional resolution requires a bound signed conditional source");
  const inputSince = canonicalU64(since,"input_since");
  requireValue(Array.isArray(resolutions) && resolutions.length === capability.transfers.length,
    "conditional resolutions must cover every transfer exactly once");
  const capacities = capability.settled_capacities.map(value=>BigInt(value)) as [bigint,bigint];
  const batch = evidence.descriptor.slice(100+evidence.summary.vault_count*97+36);
  const witness = new Uint8Array(4+BATCH_DESCRIPTOR_BYTES+8*33);
  witness.set(little(1,2));witness[2]=resolutions.length;witness.set(batch,4);
  for (let index=0;index<resolutions.length;index++) {
    const resolution=resolutions[index]!;
    const transfer=capability.transfers[index]!;
    requireValue(typeof resolution === "object" && resolution !== null
      && (resolution.kind === "fulfill" || resolution.kind === "refund")
      && Object.keys(resolution).sort().join(",") === (resolution.kind === "fulfill" ? "kind,preimage,transfer_id" : "kind,transfer_id")
      && resolution.transfer_id === transfer.transfer_id,"conditional resolutions must be unique, ordered and match signed transfers");
    const offset=4+BATCH_DESCRIPTOR_BYTES+index*33;
    const payer=transfer.payer_lock_hash === hex(evidence.descriptor.slice(4,36)) ? 0 : 1;
    let recipient: number;
    if (resolution.kind === "fulfill") {
      const preimage=bytes(resolution.preimage,32);
      requireValue(preimage.length === 32 && hex(transfer.hash_algorithm === "sha256" ? sha256(preimage) : hash(preimage)) === transfer.payment_hash,
        "conditional preimage does not match signed payment hash");
      recipient=1-payer;witness[offset]=1;witness.set(preimage,offset+1);
    } else {
      requireValue(inputSince <= 0x00ff_ffff_ffff_ffffn && inputSince >= BigInt(transfer.refund_after_block),
        "conditional refund requires mature canonical absolute-block since");
      recipient=payer;witness[offset]=2;
    }
    capacities[recipient]! += BigInt(transfer.amount);
    requireValue(capacities[recipient]! <= MAX_U64,"conditional resolved capacity overflow");
  }
  return {witness,inspection:{schema:"morph.conditional_batch_package.v1",source:evidence.summary,
    batch_id:capability.batch_id,batch_lock_hash:capability.batch_lock_hash,transfer_count:resolutions.length,
    total_capacity:(capacities[0]+capacities[1]).toString(),
    descriptor_commitment:hex(domainHash("CKB_MORPH_SETTLEMENT_DESCRIPTOR",batch)),input_since:since,
    resolved_capacities:[capacities[0].toString(),capacities[1].toString()]}};
}

/** Resolve the signed current capability, without creating another signer or
 * inferring authority from detached channel metadata. Chain publication and
 * the live Batch OutPoint still require canonical transaction evidence. */
export function createConditionalBatchPackage(source: MultiAssetRecoveryPackage, resolutions: ConditionalResolution[], inputSince: string): ConditionalBatchPackage {
  const resolved=conditionalResolutionEvidence(source,resolutions,inputSince);
  return {schema:"morph.conditional_batch_package.v1",source_package:source,resolutions,input_since:inputSince,
    resolution_witness_hex:hex(resolved.witness),resolved_capacities:resolved.inspection.resolved_capacities};
}

export function inspectConditionalBatchPackage(value: ConditionalBatchPackage): ConditionalBatchPackageInspection {
  requireValue(typeof value === "object" && value !== null && value.schema === "morph.conditional_batch_package.v1"
    && Object.keys(value).sort().join(",") === "input_since,resolution_witness_hex,resolutions,resolved_capacities,schema,source_package",
    "unsupported conditional package fields");
  const resolved=conditionalResolutionEvidence(value.source_package,value.resolutions,value.input_since);
  requireValue(same(bytes(value.resolution_witness_hex,resolved.witness.length),resolved.witness),"conditional resolution witness mismatch");
  requireValue(Array.isArray(value.resolved_capacities) && value.resolved_capacities.length === 2
    && value.resolved_capacities.every((capacity,index)=>typeof capacity === "string" && capacity === resolved.inspection.resolved_capacities[index]),
    "conditional resolved capacities mismatch");
  return resolved.inspection;
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
  capability: MultiAssetSettlementCapabilityInspection;
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
  const descriptor = bytes(descriptorHex, MAX_DESCRIPTOR_BYTES);
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
  const descriptor = bytes(proposal.descriptor_hex, MAX_DESCRIPTOR_BYTES);
  const payouts = summary.assets.map((_, index) => {
    const offset = 100 + index * 97;
    const id = asset(descriptor, offset);
    const values = [allocation(descriptor, offset + 33, id, false), allocation(descriptor, offset + 65, id, false)];
    return { type_hash: id.kind === 0 ? null : hex(id.type),
      allocations: values.map(value => ({ reserve: value.reserve.toString(), business_ckb: value.business.toString(), amount: value.amount.toString() })) as MultiAssetProposalInspection["payouts"][number]["allocations"] };
  });
  return { summary, participant_lock_hashes: [hex(descriptor.slice(4, 36)), hex(descriptor.slice(36, 68))],
    capability: settlementCapability(descriptor,summary.vault_count,bytes(evidence.header_hex,318)).inspection, payouts };
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
  capability: MultiAssetSettlementCapabilityInspection;
  input_count: number;
  output_count: number;
}
export interface MultiAssetRootFunding {
  schema: "morph.multi_asset_root_funding.v1";
  transaction_hex: string;
  recovery_package: MultiAssetRecoveryPackage;
}

const MAX_FUNDING_BYTES = 256 * 1024;
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
    assets: next.summary.assets, capability: next.capability.inspection,
    payouts: creation.vaults.map((vault, i) => ({type_hash: vault.asset.kind === 0 ? null : hex(vault.asset.type),
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
  capability: MultiAssetSettlementCapabilityInspection;
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
    capability: exit.capability.inspection,
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
