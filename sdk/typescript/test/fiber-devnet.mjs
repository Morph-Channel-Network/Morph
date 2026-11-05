import assert from "node:assert/strict";
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";

import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  MorphAgentClient,
  MorphAgentError,
  createSignedPaymentPayload,
  decryptFairExchange,
  deriveMorphAccountId,
  verifySignedPaymentPayload,
} from "../dist/index.js";

const payeeUrl = requiredEnv("MORPH_AGENT_PAYEE_URL");
const payerUrl = requiredEnv("MORPH_AGENT_PAYER_URL");
const ckbNetworkId = requiredByte32Env("MORPH_AGENT_CKB_NETWORK_ID");
if (Object.hasOwn(process.env, "MORPH_AGENT_PAYER_PRIVATE_KEY")) {
  throw new Error("raw payer key input is unsupported; use MORPH_AGENT_PAYER_PRIVATE_KEY_FILE");
}
const privateKey = protectedPayerKeyFile(requiredEnv("MORPH_AGENT_PAYER_PRIVATE_KEY_FILE"));
const expectedPayee = requiredByte32Env("MORPH_AGENT_EXPECTED_PAYEE");
const expectedFiberRoute = [
  requiredPubkeyEnv("MORPH_AGENT_FIBER_NODE1_PUBKEY"),
  requiredPubkeyEnv("MORPH_AGENT_FIBER_NODE2_PUBKEY"),
  requiredPubkeyEnv("MORPH_AGENT_FIBER_NODE3_PUBKEY"),
];

const payerPublicKey = secp256k1.getPublicKey(privateKey, true);
const payer = deriveMorphAccountId(payerPublicKey);
assert.notEqual(payer, expectedPayee, "payer and payee identities must differ");

const asset = {
  kind: "ckb",
  ckb_network_id: ckbNetworkId,
  symbol: "CKB",
  decimals: 8,
};
const payeeAgent = new MorphAgentClient(payeeUrl);
const payerAgent = new MorphAgentClient(payerUrl);

const supported = await payeeAgent.supported();
assert.equal(supported.payee, expectedPayee);
assert.ok(Array.isArray(supported.capabilities));
assert.ok(supported.capabilities.includes("x402_exact"));
assert.ok(supported.capabilities.includes("biscuit_credentials"));
assert.ok(supported.capabilities.includes("fair_exchange_aes_256_gcm"));

const requirement = await payeeAgent.createX402Challenge({
  asset,
  amount: "400",
  payer,
  resource: "/devnet/agent-result",
  operation: "GET",
  description: "Morph issue 1255 real Fiber devnet payment",
  expires_in_seconds: 300,
});
assert.equal(requirement.payer, payer);
assert.equal(requirement.payee, expectedPayee);
const payload = createSignedPaymentPayload(requirement, privateKey);
assert.equal(verifySignedPaymentPayload(requirement, payload), true);

await assert.rejects(
  payeeAgent.settle({ requirements: requirement, payload }),
  error => error instanceof MorphAgentError && error.status === 402,
  "settlement must fail before Fiber reports the invoice paid",
);

const outgoing = await payerAgent.pay({
  requirements: requirement,
  payload,
  timeout_seconds: 60,
  max_fee_amount: "1000",
});
assert.equal(outgoing.payment_hash, requirement.payment_hash);
assert.equal(outgoing.completed, true);
const x402Route = requireThreeNodeFiberRoute(outgoing.fiber_result, expectedFiberRoute);

const settlement = await retryPaymentRequired(() =>
  payeeAgent.settle({ requirements: requirement, payload }),
);
assert.equal(settlement.receipt.requirement_id, requirement.requirement_id);
assert.equal(settlement.receipt.payment_hash, requirement.payment_hash);
assert.equal(settlement.receipt.payer, payer);
assert.equal(settlement.receipt.fiber_status, "Paid");
assert.equal(settlement.receipt.terminal_receipt.status, "Settled");
assert.equal(settlement.payment_preimage.length, 66);

const authorization = await payeeAgent.verifyCredential(
  settlement.receipt.credential,
  settlement.receipt,
  requirement.resource,
);
assert.equal(authorization.authorized, true);

const plaintext = new TextEncoder().encode("RGB++ Agent fair-exchange result over real Fiber");
const offer = await payeeAgent.createFairOffer({
  asset,
  amount: "401",
  payer,
  resource: "/devnet/fair-exchange",
  operation: "POST",
  plaintext_base64: Buffer.from(plaintext).toString("base64"),
  description: "Morph hash-locked data exchange over Fiber",
  expires_in_seconds: 300,
});
const fairPayload = createSignedPaymentPayload(offer.requirement, privateKey);
const fairOutgoing = await payerAgent.pay({
  requirements: offer.requirement,
  payload: fairPayload,
  timeout_seconds: 60,
  max_fee_amount: "1000",
});
assert.equal(fairOutgoing.completed, true);
const fairExchangeRoute = requireThreeNodeFiberRoute(
  fairOutgoing.fiber_result,
  expectedFiberRoute,
);
const claim = await retryPaymentRequired(() =>
  payeeAgent.claimFairOffer(offer.offer_id, fairPayload),
);
assert.deepEqual(await decryptFairExchange(offer, claim), plaintext);

const [incomingIndex, outgoingIndex] = await Promise.all([
  payeeAgent.payments(20),
  payerAgent.payments(20),
]);
assert.ok(incomingIndex.payments.some(payment =>
  payment.payment_hash === requirement.payment_hash && payment.status === "Paid"
));
assert.ok(outgoingIndex.payments.some(payment =>
  payment.payment_hash === requirement.payment_hash && payment.status === "Success"
));

privateKey.fill(0);

console.log(JSON.stringify({
  schema: "morph.agent_fiber_devnet_e2e",
  status: "passed",
  route: "fiber-node1 -> fiber-node2 -> fiber-node3",
  payer,
  payee: expectedPayee,
  ckb_network_id: ckbNetworkId,
  routing: {
    x402_node_pubkeys: x402Route,
    fair_exchange_node_pubkeys: fairExchangeRoute,
  },
  x402: {
    payment_hash: requirement.payment_hash,
    receipt_id: settlement.receipt.receipt_id,
    credential_id: settlement.receipt.credential_id,
    terminal_status: settlement.receipt.terminal_receipt.status,
  },
  fair_exchange: {
    payment_hash: offer.requirement.payment_hash,
    offer_id: offer.offer_id,
    receipt_id: claim.receipt.receipt_id,
    plaintext_sha256: offer.result_hash,
  },
}));

async function retryPaymentRequired(operation) {
  let lastError;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!(error instanceof MorphAgentError) || error.status !== 402) throw error;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
  throw lastError;
}

// This is an isolated development test input, with the same file boundary as
// the Rust binaries. Paths are the only secret-related environment values.
function protectedPayerKeyFile(path) {
  if (typeof process.getuid !== "function" || typeof fsConstants.O_NOFOLLOW !== "number"
      || typeof fsConstants.O_NONBLOCK !== "number") {
    throw new Error("protected payer key files are unsupported on this platform");
  }
  let fd;
  const buffer = Buffer.alloc(257);
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0
        || stat.size > 256) throw new Error("invalid protected file");
    const count = readSync(fd, buffer, 0, buffer.length, 0);
    if (count > 256) throw new Error("oversized protected file");
    const text = buffer.subarray(0, count).toString("utf8").replace(/^[\t-\r ]+|[\t-\r ]+$/g, "");
    const key = decodeHex(text, 32);
    // Validate the scalar before any RPC operation and keep failures secret-safe.
    try {
      secp256k1.getPublicKey(key, true);
    } catch {
      key.fill(0);
      throw new Error("invalid scalar");
    }
    return key;
  } catch {
    throw new Error("protected payer key file is invalid or inaccessible");
  } finally {
    buffer.fill(0);
    if (fd !== undefined) closeSync(fd);
  }
}

function requiredEnv(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function requiredByte32Env(name) {
  const value = requiredEnv(name);
  decodeHex(value, 32);
  return value.toLowerCase();
}

function requiredPubkeyEnv(name) {
  const value = requiredEnv(name).toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{66}$/.test(value)) throw new Error(`${name} must be a compressed public key`);
  return value;
}

function requireThreeNodeFiberRoute(fiberResult, expectedRoute) {
  assert.ok(fiberResult !== null && typeof fiberResult === "object");
  assert.ok(Array.isArray(fiberResult.routers), "debug Fiber result must expose routers");
  assert.equal(fiberResult.routers.length, 1, "devnet payment must use one completed part");
  const nodes = fiberResult.routers[0]?.nodes;
  assert.ok(Array.isArray(nodes), "Fiber route must expose its nodes");
  const actualRoute = nodes.map(node => {
    assert.ok(node !== null && typeof node === "object");
    assert.equal(typeof node.pubkey, "string");
    return node.pubkey.toLowerCase().replace(/^0x/, "");
  });
  assert.deepEqual(actualRoute, expectedRoute, "payment must traverse node1 -> node2 -> node3");
  return actualRoute;
}

function decodeHex(value, expectedLength) {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (raw.length !== expectedLength * 2 || !/^[0-9a-fA-F]+$/u.test(raw)) {
    throw new Error(`expected ${expectedLength}-byte hexadecimal value`);
  }
  return Uint8Array.from(Buffer.from(raw, "hex"));
}
