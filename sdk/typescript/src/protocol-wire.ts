// Shared current CKB byte, hash, asset and Molecule primitives.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
export const MAX_U64 = (1n << 64n) - 1n;
export const MAX_SCRIPT_BYTES = 512;
export const MAX_TRANSACTION_BYTES = 512 * 1024;
export const utf8 = new TextEncoder();
export function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new TypeError(`invalid Morph protocol evidence: ${message}`);
}

export function bytes(raw: string, max: number): Uint8Array {
  requireValue(typeof raw === "string" && raw.length <= 2 + 2 * max && /^0x(?:[0-9a-f]{2})*$/.test(raw), "noncanonical hex or byte limit exceeded");
  return Uint8Array.from(raw.slice(2).match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

export function hex(raw: Uint8Array): string {
  return `0x${Array.from(raw, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function join(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

export function hash(...parts: Uint8Array[]): Uint8Array {
  return blake2b(join(...parts), { dkLen: 32, personalization: utf8.encode("ckb-default-hash") });
}

export function domainHash(domain: string, ...parts: Uint8Array[]): Uint8Array {
  return hash(utf8.encode(domain), ...parts);
}

export function same(a: Uint8Array, b: Uint8Array): boolean { return hex(a) === hex(b); }
export function zero(raw: Uint8Array): boolean { return raw.every((byte) => byte === 0); }

export function unsigned(raw: Uint8Array, offset: number, length: number): bigint {
  requireValue(offset >= 0 && offset + length <= raw.length, "truncated integer");
  let value = 0n;
  for (let i = length - 1; i >= 0; i--) value = (value << 8n) | BigInt(raw[offset + i]!);
  return value;
}
export function u16(raw: Uint8Array, offset: number): number { return Number(unsigned(raw, offset, 2)); }
export function u32(raw: Uint8Array, offset: number): number { return Number(unsigned(raw, offset, 4)); }
export function little(value: number | bigint, length: number): Uint8Array {
  let remaining = BigInt(value);
  return Uint8Array.from({ length }, () => { const byte = Number(remaining & 255n); remaining >>= 8n; return byte; });
}

export interface Asset { kind: number; type: Uint8Array; key: string }
export interface Allocation { reserve: bigint; business: bigint; amount: bigint; capacity: bigint }
export interface Vault { asset: Asset; lock: Uint8Array; value: Allocation }


export function asset(raw: Uint8Array, offset: number): Asset {
  requireValue(offset + 33 <= raw.length, "truncated asset");
  const kind = raw[offset]!;
  const type = raw.slice(offset + 1, offset + 33);
  requireValue((kind === 0 && zero(type)) || (kind === 1 && !zero(type)), "unknown asset identity");
  return { kind, type, key: hex(raw.slice(offset, offset + 33)) };
}

export function allocation(raw: Uint8Array, offset: number, id: Asset, vault: boolean): Allocation {
  const reserve = unsigned(raw, offset, 8);
  const business = unsigned(raw, offset + 8, 8);
  const amount = unsigned(raw, offset + 16, 16);
  const capacity = reserve + business;
  requireValue(capacity <= MAX_U64 && (id.kind !== 0 || amount === 0n)
    && (capacity !== 0n || amount === 0n) && (capacity === 0n || reserve > 0n)
    && (!vault || (capacity > 0n && (id.kind === 0 || amount > 0n))), "invalid allocation or overflow");
  return { reserve, business, amount, capacity };
}

export function scriptOccupied(raw: Uint8Array): bigint {
  requireValue(raw.length >= 53 && raw.length <= MAX_SCRIPT_BYTES
    && u32(raw, 0) === raw.length && u32(raw, 4) === 16 && u32(raw, 8) === 48
    && u32(raw, 12) === 49 && u32(raw, 49) === raw.length - 53
    && [0, 1, 2, 4].includes(raw[48]!), "noncanonical CKB Script");
  return BigInt(33 + raw.length - 53);
}

export function occupied(lock: Uint8Array, type?: Uint8Array): bigint {
  return (8n + scriptOccupied(lock) + (type === undefined ? 0n : scriptOccupied(type) + 16n)) * 100_000_000n;
}


export function table(raw: Uint8Array, count: number): Uint8Array[] {
  requireValue(raw.length >= 4 * (count + 1) && u32(raw, 0) === raw.length && u32(raw, 4) === 4 * (count + 1), "noncanonical Molecule table");
  const offsets = Array.from({length: count}, (_, i) => u32(raw, 4 + i * 4));
  offsets.push(raw.length);
  requireValue(offsets.every((offset, i) => offset <= raw.length && (i === 0 || offset >= offsets[i - 1]!)), "invalid Molecule offsets");
  return offsets.slice(0, -1).map((offset, i) => raw.slice(offset, offsets[i + 1]));
}
export function dynamic(raw: Uint8Array, max: number): Uint8Array[] {
  requireValue(raw.length >= 4 && u32(raw, 0) === raw.length, "invalid Molecule vector");
  if (raw.length === 4) return [];
  const first = u32(raw, 4);
  requireValue(first >= 8 && first % 4 === 0 && first / 4 - 1 <= max, "Molecule vector exceeds count bound");
  return table(raw, first / 4 - 1);
}
export function fixed(raw: Uint8Array, size: number, max: number): Uint8Array[] {
  const count = u32(raw, 0);
  requireValue(count <= max && raw.length === 4 + size * count, "invalid Molecule fixed vector");
  return Array.from({length: count}, (_, i) => raw.slice(4 + i * size, 4 + (i + 1) * size));
}
export function byteVector(raw: Uint8Array): Uint8Array {
  requireValue(raw.length >= 4 && u32(raw, 0) === raw.length - 4, "invalid Molecule Bytes");
  return raw.slice(4);
}
export function encodeTable(fields: Uint8Array[]): Uint8Array {
  let offset = 4 * (fields.length + 1);
  const offsets = fields.map((field) => { const start = offset; offset += field.length; return little(start, 4); });
  return join(little(offset, 4), ...offsets, ...fields);
}
export function encodeDynamic(fields: Uint8Array[]): Uint8Array { return fields.length === 0 ? little(4, 4) : encodeTable(fields); }
export function encodeBytes(raw: Uint8Array): Uint8Array { return join(little(raw.length, 4), raw); }
export interface RawTransactionEvidence {
  raw: Uint8Array;
  fields: Uint8Array[];
  inputs: Uint8Array[];
  outputs: Array<{capacity: bigint; lock: Uint8Array; type: Uint8Array | undefined; data: Uint8Array}>;
  dependencies: Array<{tx_hash:string;index:number;dep_type:"code"|"dep_group"}>;
}
export function rawTransactionEvidence(body: Uint8Array): RawTransactionEvidence {
  const fields = table(body!, 6);
  requireValue(fields[0]!.length === 4 && u32(fields[0]!, 0) === 0, "unsupported root transaction version");
  const dependencies = fixed(fields[1]!, 37, 64).map((dep) => {
    requireValue(dep[36] === 0 || dep[36] === 1, "unsupported dependency type");
    return {tx_hash: hex(dep.slice(0, 32)), index: u32(dep, 32), dep_type: dep[36] === 0 ? "code" as const : "dep_group" as const};
  }).sort((a, b) => a.tx_hash < b.tx_hash ? -1 : a.tx_hash > b.tx_hash ? 1 : a.index - b.index);
  fixed(fields[2]!, 32, 64);
  const inputs = fixed(fields[3]!, 44, 64);
  requireValue(inputs.length > 0, "missing transaction inputs");
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
  return {raw:body, fields,inputs,outputs,dependencies};
}
export interface TransactionEvidence extends RawTransactionEvidence { witnesses: Uint8Array[]; witnessFields: Uint8Array[] }
export function transactionEvidence(raw:Uint8Array,emptyMorphWitness=false):TransactionEvidence {
  const [body,witnessVector]=table(raw,2);
  const evidence=rawTransactionEvidence(body!);
  requireValue(evidence.dependencies.length > 0,"missing root dependencies");
  const witnesses = dynamic(witnessVector!, MAX_TRANSACTION_BYTES / 8).map(byteVector);
  requireValue(emptyMorphWitness || witnesses.length > 0, "missing transaction witness zero");
  const witnessFields = emptyMorphWitness && (witnesses[0]?.length ?? 0) === 0
    ? [new Uint8Array(), new Uint8Array(), new Uint8Array()] : table(witnesses[0]!, 3);
  return {...evidence,witnesses,witnessFields};
}
export function validPublicKey(key: Uint8Array): boolean {
  if (key.length !== 33) return false;
  try { secp256k1.Point.fromBytes(key); return true; } catch { return false; }
}
