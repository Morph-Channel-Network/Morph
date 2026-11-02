import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { inspectMultiAssetPackage, type MultiAssetRecoveryPackage } from "./multi-asset.js";
export * from "./multi-asset.js";

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export type AssetKind = "ckb" | "rgbpp";
export type BitcoinNetwork = "mainnet" | "testnet" | "signet" | "regtest";

export interface RgbppAsset {
  kind: AssetKind;
  ckb_network_id: string;
  type_script_hash?: string;
  type_script?: Record<string, unknown>;
  bitcoin_network?: BitcoinNetwork;
  binding_code_hash?: string;
  symbol: string;
  decimals: number;
}

export interface PaymentRequirements {
  requirement_id: string;
  scheme: "exact";
  network: "morph-ckb";
  payment_rail: "fiber";
  asset: RgbppAsset;
  amount: string;
  payer: string;
  payee: string;
  invoice: string;
  payment_hash: string;
  hash_algorithm: "sha256";
  resource: string;
  operation: string;
  nonce: string;
  rgbpp_proof_commitment?: string;
  expires_at: number;
}

export interface PaymentPayload {
  requirement_id: string;
  payment_hash: string;
  payer: string;
  payer_pubkey_sec1: string;
  payer_signature: string;
  payment_preimage?: string;
}

export interface PaymentReceipt {
  receipt_id: string;
  credential_id: string;
  requirement_id: string;
  payment_hash: string;
  payer: string;
  asset_id: string;
  amount: string;
  resource: string;
  operation: string;
  paid_at: number;
  fiber_status: string;
  credential: string;
  credential_expires_at: number;
  intent: Record<string, unknown>;
  terminal_receipt: Record<string, unknown>;
}

export interface FairExchangeEnvelope {
  offer_id: string;
  requirement: PaymentRequirements;
  nonce: string;
  ciphertext: string;
  result_hash: string;
}

export interface FairExchangeClaim {
  offer_id: string;
  decryption_key: string;
  receipt: PaymentReceipt;
}

export type ConditionalHashAlgorithm = "ckb_blake2b" | "sha256";

export interface ConditionalTransfer {
  transfer_id: string;
  payer_lock_hash: string;
  hash_algorithm: ConditionalHashAlgorithm;
  payment_hash: string;
  amount: number;
  refund_after_block: number;
}

export type ConditionalResolution =
  | { kind: "fulfill"; transfer_id: string; preimage: string }
  | { kind: "refund"; transfer_id: string };

export interface ConditionalBatchPackage {
  schema: "morph.conditional_batch_package";
  channel_id: string;
  funding_context_id: string;
  state_number: number;
  batch_id: string;
  application_context_commitment: string;
  participants: Array<{ settlement_lock_hash: string; settled_capacity: number }>;
  transfers: ConditionalTransfer[];
  resolutions: ConditionalResolution[];
  input_since: number;
  descriptor_hex: string;
  descriptor_commitment: string;
  resolution_witness_hex: string;
  resolved_capacities: [number, number];
}

/** Authenticated client for durable conditional recovery packages in Morph Hub. */
export class MorphHubClient {
  private readonly baseUrl: URL;

  constructor(
    baseUrl: string,
    private readonly bearerToken?: string,
  ) {
    this.baseUrl = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    if (
      this.baseUrl.protocol !== "https:"
      && !(this.baseUrl.protocol === "http:" && isLoopbackHostname(this.baseUrl.hostname))
    ) {
      throw new TypeError("Morph Hub URL must use HTTPS unless it is loopback HTTP");
    }
    if (bearerToken !== undefined && bearerToken.length < 32) {
      throw new TypeError("Morph Hub bearer token must contain at least 32 bytes");
    }
  }

  state(): Promise<Record<string, unknown>> {
    return this.request("api/state");
  }

  importConditionalBatch(value: ConditionalBatchPackage): Promise<Record<string, unknown>> {
    if (value.schema !== "morph.conditional_batch_package") {
      throw new TypeError("unsupported conditional batch package schema");
    }
    return this.request("api/conditional-batches", value);
  }

  importMultiAssetPackage(value: MultiAssetRecoveryPackage): Promise<Record<string, unknown>> {
    inspectMultiAssetPackage(value);
    return this.request("api/multi-asset-packages", value);
  }

  async multiAssetPackage(packageId: string): Promise<MultiAssetRecoveryPackage> {
    if (!/^0x[0-9a-f]{64}$/.test(packageId)) throw new TypeError("invalid multi-asset package id");
    const value = await this.request(`api/multi-asset-packages/${packageId}`);
    const result = value as unknown as MultiAssetRecoveryPackage;
    const summary = inspectMultiAssetPackage(result);
    if (summary.package_id !== packageId) throw new Error("Morph Hub returned a different multi-asset package");
    return result;
  }

  private async request(path: string, body?: unknown): Promise<Record<string, unknown>> {
    const response = await fetch(new URL(path, this.baseUrl), {
      method: body === undefined ? "GET" : "POST",
      headers: {
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(this.bearerToken === undefined
          ? {}
          : { authorization: `Bearer ${this.bearerToken}` }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: "error",
    });
    const decoded = await readJsonResponseLimited(response, MAX_RESPONSE_BYTES);
    if (!response.ok) {
      const message = isRecord(decoded) && typeof decoded.error === "string"
        ? decoded.error
        : "Morph Hub request failed";
      throw new MorphAgentError(message, response.status);
    }
    if (!isRecord(decoded)) throw new Error("Morph Hub returned a non-object response");
    return decoded;
  }
}

export class MorphAgentError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "MorphAgentError";
  }
}

/** Browser/Node client for the standalone Morph Agent HTTP API. */
export class MorphAgentClient {
  private readonly baseUrl: URL;
  private readonly apiBearerToken: string | undefined;

  constructor(baseUrl: string, options: { apiBearerToken?: string } = {}) {
    this.baseUrl = new URL(baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    if (
      this.baseUrl.protocol !== "https:"
      && !(this.baseUrl.protocol === "http:" && isLoopbackHostname(this.baseUrl.hostname))
    ) {
      throw new TypeError("Morph Agent URL must use HTTPS unless it is loopback HTTP");
    }
    if (options.apiBearerToken !== undefined && options.apiBearerToken.length < 32) {
      throw new TypeError("Morph Agent API bearer token must contain at least 32 bytes");
    }
    this.apiBearerToken = options.apiBearerToken;
  }

  supported(): Promise<Record<string, unknown>> {
    return this.request("v1/supported");
  }

  createChallenge(input: {
    asset: RgbppAsset;
    amount: string;
    payer: string;
    resource: string;
    operation: string;
    description?: string;
    expires_in_seconds?: number;
    rgbpp_proof_commitment?: string;
  }): Promise<PaymentRequirements> {
    return this.request("v1/challenges", input);
  }

  async createX402Challenge(input: {
    asset: RgbppAsset;
    amount: string;
    payer: string;
    resource: string;
    operation: string;
    description?: string;
    expires_in_seconds?: number;
    rgbpp_proof_commitment?: string;
  }): Promise<PaymentRequirements> {
    const response = await fetch(new URL("v1/x402/challenge", this.baseUrl), {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify(input),
      redirect: "error",
    });
    if (response.status !== 402) {
      throw new MorphAgentError("Morph Agent did not return an x402 challenge", response.status);
    }
    const header = response.headers.get("payment-required");
    if (header === null) throw new Error("x402 challenge is missing PAYMENT-REQUIRED");
    return decodeX402Header<PaymentRequirements>(header);
  }

  pay(input: {
    requirements: PaymentRequirements;
    payload: PaymentPayload;
    timeout_seconds?: number;
    max_fee_amount?: string;
  }): Promise<{ completed: boolean; payment_hash: string; fiber_result: unknown }> {
    return this.request("v1/pay", input);
  }

  verify(input: {
    requirements: PaymentRequirements;
    payload: PaymentPayload;
  }): Promise<{ valid: boolean; payment_hash: string; fiber_status: string }> {
    return this.request("v1/x402/verify", input);
  }

  settle(input: {
    requirements: PaymentRequirements;
    payload: PaymentPayload;
    credential_ttl_seconds?: number;
  }): Promise<{ receipt: PaymentReceipt; payment_preimage: string }> {
    return this.request("v1/x402/settle", input);
  }

  verifyCredential(
    credential: string,
    receipt: PaymentReceipt,
    resource = receipt.resource,
  ): Promise<{ authorized: boolean }> {
    return this.request("v1/credentials/verify", { credential, receipt, resource });
  }

  createFairOffer(input: {
    asset: RgbppAsset;
    amount: string;
    payer: string;
    resource: string;
    operation: string;
    plaintext_base64: string;
    description?: string;
    expires_in_seconds?: number;
    rgbpp_proof_commitment?: string;
  }): Promise<FairExchangeEnvelope> {
    return this.request("v1/fair-exchange/offers", input);
  }

  claimFairOffer(
    offer_id: string,
    payload: PaymentPayload,
    credential_ttl_seconds?: number,
  ): Promise<FairExchangeClaim> {
    return this.request("v1/fair-exchange/claims", {
      offer_id,
      payload,
      ...(credential_ttl_seconds === undefined ? {} : { credential_ttl_seconds }),
    });
  }

  payments(limit = 100): Promise<Record<string, unknown>> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
      throw new RangeError("limit must be an integer from 1 through 1000");
    }
    return this.request(`v1/payments?limit=${limit}`);
  }

  private async request<T>(path: string, body?: unknown): Promise<T> {
    const init: RequestInit = body === undefined
      ? { method: "GET", headers: this.headers(false), redirect: "error" }
      : {
          method: "POST",
          headers: this.headers(true),
          body: JSON.stringify(body),
          redirect: "error",
        };
    const response = await fetch(new URL(path, this.baseUrl), init);
    const value = await readJsonResponseLimited(response, MAX_RESPONSE_BYTES);
    if (!response.ok) {
      const message = isRecord(value) && typeof value.error === "string"
        ? value.error
        : "Morph Agent request failed";
      throw new MorphAgentError(message, response.status);
    }
    return value as T;
  }

  private headers(json: boolean): Record<string, string> {
    return {
      ...(json ? { "content-type": "application/json" } : {}),
      ...(this.apiBearerToken === undefined
        ? {}
        : { authorization: `Bearer ${this.apiBearerToken}` }),
    };
  }
}

async function readJsonResponseLimited(response: Response, maximum: number): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0 || parsedLength > maximum) {
      throw new Error("Morph Agent response exceeds the maximum size");
    }
  }

  if (response.body === null) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        await reader.cancel();
        throw new Error("Morph Agent response exceeds the maximum size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
}

function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "[::1]" || host === "::1") return true;
  const octets = host.split(".");
  return octets.length === 4
    && octets[0] === "127"
    && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

export interface X402SettleRequest {
  requirements: PaymentRequirements;
  payload: PaymentPayload;
  credential_ttl_seconds?: number;
}

const PAYER_AUTHORIZATION_DOMAIN = new TextEncoder().encode("CKB_MORPH_X402_PAYER_AUTH_V1");
const CKB_HASH_PERSONALIZATION = new TextEncoder().encode("ckb-default-hash");

/** Derive the canonical Morph account ID from a compressed secp256k1 key. */
export function deriveMorphAccountId(publicKey: Uint8Array): string {
  if (publicKey.length !== 33 || !secp256k1.utils.isValidPublicKey(publicKey, true)) {
    throw new Error("expected a compressed secp256k1 public key");
  }
  return encodeHex(blake2b(publicKey, {
    dkLen: 32,
    personalization: CKB_HASH_PERSONALIZATION,
  }));
}

/**
 * Sign an x402 payload with the payer's secp256k1 key. The signature binds the
 * exact requirement ID, payment hash, derived payer, and optional preimage.
 */
export function createSignedPaymentPayload(
  requirements: PaymentRequirements,
  privateKey: string | Uint8Array,
  paymentPreimage?: string,
): PaymentPayload {
  const secretKey = typeof privateKey === "string" ? decodeHex(privateKey, 32) : privateKey;
  if (secretKey.length !== 32 || !secp256k1.utils.isValidSecretKey(secretKey)) {
    throw new Error("expected a valid 32-byte secp256k1 private key");
  }
  const publicKey = secp256k1.getPublicKey(secretKey, true);
  const payer = deriveMorphAccountId(publicKey);
  if (payer !== requirements.payer) throw new Error("private key does not match challenge payer");
  if (payer === requirements.payee) throw new Error("payer and payee must differ");
  const digest = payerAuthorizationDigest(requirements, payer, paymentPreimage);
  const signature = secp256k1.sign(digest, secretKey, {
    prehash: false,
    lowS: true,
    format: "compact",
  });
  return {
    requirement_id: requirements.requirement_id,
    payment_hash: requirements.payment_hash,
    payer,
    payer_pubkey_sec1: encodeHex(publicKey),
    payer_signature: encodeHex(signature),
    ...(paymentPreimage === undefined ? {} : { payment_preimage: paymentPreimage }),
  };
}

/** Verify payer ownership and payload binding before sending it to an Agent. */
export function verifySignedPaymentPayload(
  requirements: PaymentRequirements,
  payload: PaymentPayload,
): boolean {
  try {
    if (payload.requirement_id !== requirements.requirement_id
      || payload.payment_hash !== requirements.payment_hash
      || payload.payer !== requirements.payer
      || payload.payer === requirements.payee) return false;
    const publicKey = decodeHex(payload.payer_pubkey_sec1, 33);
    if (deriveMorphAccountId(publicKey) !== payload.payer) return false;
    const signature = decodeHex(payload.payer_signature, 64);
    const digest = payerAuthorizationDigest(
      requirements,
      payload.payer,
      payload.payment_preimage,
    );
    return secp256k1.verify(signature, digest, publicKey, {
      prehash: false,
      lowS: true,
      format: "compact",
    });
  } catch {
    return false;
  }
}

function payerAuthorizationDigest(
  requirements: PaymentRequirements,
  payer: string,
  paymentPreimage?: string,
): Uint8Array {
  const preimage = paymentPreimage === undefined ? undefined : decodeHex(paymentPreimage, 32);
  return nobleSha256(concatByteArrays(
    PAYER_AUTHORIZATION_DOMAIN,
    decodeHex(requirements.requirement_id, 32),
    decodeHex(requirements.payment_hash, 32),
    decodeHex(payer, 32),
    new Uint8Array([preimage === undefined ? 0 : 1]),
    ...(preimage === undefined ? [] : [preimage]),
  ));
}

/** Encode a Morph x402 JSON payload as unpadded base64url. */
export function encodeX402Header(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

/** Decode and parse an unpadded base64url Morph x402 header. */
export function decodeX402Header<T>(value: string): T {
  if (value.length > 64 * 1024 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error("invalid or oversized Morph x402 header");
  }
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/**
 * Access a protected Morph Gateway resource with a one-shot PAYMENT-SIGNATURE.
 * The returned signed terminal receipt is taken from PAYMENT-RESPONSE.
 */
export async function x402Fetch(
  resourceUrl: string | URL,
  settlement: X402SettleRequest,
  init: RequestInit = {},
): Promise<{ response: Response; receipt: PaymentReceipt }> {
  const headers = new Headers(init.headers);
  if (headers.has("authorization")) {
    throw new Error("do not combine Authorization with PAYMENT-SIGNATURE");
  }
  headers.set("payment-signature", encodeX402Header(settlement));
  const response = await fetch(resourceUrl, { ...init, headers, redirect: "error" });
  if (!response.ok) {
    throw new MorphAgentError("Morph x402 Gateway request failed", response.status);
  }
  const encodedReceipt = response.headers.get("payment-response");
  if (encodedReceipt === null) throw new Error("Gateway response is missing PAYMENT-RESPONSE");
  return { response, receipt: decodeX402Header<PaymentReceipt>(encodedReceipt) };
}

/**
 * Verify the SHA-256 payment preimage, decrypt an AES-256-GCM fair-exchange
 * envelope, and verify the committed result hash. No server trust is needed for
 * these three checks after the claim has returned the key.
 */
export async function decryptFairExchange(
  envelope: FairExchangeEnvelope,
  claim: FairExchangeClaim,
): Promise<Uint8Array> {
  if (claim.offer_id !== envelope.offer_id) {
    throw new Error("fair-exchange claim belongs to another offer");
  }
  const key = decodeHex(claim.decryption_key, 32);
  const paymentHash = await sha256(key);
  if (!equalBytes(paymentHash, decodeHex(envelope.requirement.payment_hash, 32))) {
    throw new Error("decryption key does not match the Fiber payment hash");
  }
  const nonce = decodeHex(envelope.nonce, 12);
  const ciphertext = decodeBase64(envelope.ciphertext);
  const associatedData = new TextEncoder().encode(
    `morph-fair-exchange-v1\0${envelope.offer_id}\0${envelope.requirement.requirement_id}`,
  );
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: associatedData },
    cryptoKey,
    ciphertext,
  ));
  if (!equalBytes(await sha256(plaintext), decodeHex(envelope.result_hash, 32))) {
    throw new Error("decrypted result does not match the committed result hash");
  }
  return plaintext;
}

function decodeHex(value: string, expectedLength: number): Uint8Array<ArrayBuffer> {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (raw.length !== expectedLength * 2 || !/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(`expected a ${expectedLength}-byte hex value`);
  }
  const decoded = new Uint8Array(expectedLength);
  for (let index = 0; index < expectedLength; index += 1) {
    decoded[index] = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
  }
  return decoded;
}

function decodeBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const decoded = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    decoded[index] = binary.charCodeAt(index);
  }
  return decoded;
}

function encodeHex(value: Uint8Array): string {
  let encoded = "0x";
  for (const byte of value) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

function concatByteArrays(...values: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

async function sha256(value: BufferSource): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
