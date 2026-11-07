import assert from "node:assert/strict";

import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  MorphPaymentGatewayClient,
  MorphPaymentGatewayError,
  createSignedPaymentPayload,
  decryptFairExchange,
  deriveMorphAccountId,
  verifySignedPaymentPayload,
} from "../dist/index.js";
import { protectedPayerKeyFromEnv } from "./protected-key-file.mjs";

// Validate local signing input before reading any RPC configuration.
const privateKey = protectedPayerKeyFromEnv();
const payeeUrl = requiredEnv("MORPH_PAYMENT_GATEWAY_PAYEE_URL");
const payerUrl = requiredEnv("MORPH_PAYMENT_GATEWAY_PAYER_URL");
const ckbNetworkId = requiredByte32Env("MORPH_PAYMENT_GATEWAY_CKB_NETWORK_ID");
const expectedPayee = requiredByte32Env("MORPH_PAYMENT_GATEWAY_EXPECTED_PAYEE");
const expectedFiberRoute = [
  requiredPubkeyEnv("MORPH_PAYMENT_GATEWAY_FIBER_NODE1_PUBKEY"),
  requiredPubkeyEnv("MORPH_PAYMENT_GATEWAY_FIBER_NODE2_PUBKEY"),
  requiredPubkeyEnv("MORPH_PAYMENT_GATEWAY_FIBER_NODE3_PUBKEY"),
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
const payeeGateway = new MorphPaymentGatewayClient(payeeUrl);
const payerGateway = new MorphPaymentGatewayClient(payerUrl);

const supported = await payeeGateway.supported();
assert.equal(supported.payee, expectedPayee);
assert.ok(Array.isArray(supported.capabilities));
assert.ok(supported.capabilities.includes("x402_exact"));
assert.ok(supported.capabilities.includes("biscuit_credentials"));
assert.ok(supported.capabilities.includes("fair_exchange_aes_256_gcm"));

const requirement = await payeeGateway.createX402Challenge({
  asset,
  amount: "400",
  payer,
  resource: "/devnet/payment-gateway-result",
  operation: "GET",
  description: "Morph issue 1255 real Fiber devnet payment",
  expires_in_seconds: 300,
});
assert.equal(requirement.payer, payer);
assert.equal(requirement.payee, expectedPayee);
const payload = createSignedPaymentPayload(requirement, privateKey);
assert.equal(verifySignedPaymentPayload(requirement, payload), true);

await assert.rejects(
  payeeGateway.settle({ requirements: requirement, payload }),
  error => error instanceof MorphPaymentGatewayError && error.status === 402,
  "settlement must fail before Fiber reports the invoice paid",
);

const outgoing = await payerGateway.pay({
  requirements: requirement,
  payload,
  timeout_seconds: 60,
  max_fee_amount: "1000",
});
assert.equal(outgoing.payment_hash, requirement.payment_hash);
assert.equal(outgoing.completed, true);
const x402Route = requireThreeNodeFiberRoute(outgoing.fiber_result, expectedFiberRoute);

const settlement = await retryPaymentRequired(() =>
  payeeGateway.settle({ requirements: requirement, payload }),
);
assert.equal(settlement.receipt.requirement_id, requirement.requirement_id);
assert.equal(settlement.receipt.payment_hash, requirement.payment_hash);
assert.equal(settlement.receipt.payer, payer);
assert.equal(settlement.receipt.fiber_status, "Paid");
assert.equal(settlement.receipt.terminal_receipt.status, "Settled");
assert.equal(settlement.payment_preimage.length, 66);

const authorization = await payeeGateway.verifyCredential(
  settlement.receipt.credential,
  settlement.receipt,
  requirement.resource,
);
assert.equal(authorization.authorized, true);

const plaintext = new TextEncoder().encode("RGB++ Morph Payment Gateway fair-exchange result over real Fiber");
const offer = await payeeGateway.createFairOffer({
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
const fairOutgoing = await payerGateway.pay({
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
  payeeGateway.claimFairOffer(offer.offer_id, fairPayload),
);
assert.deepEqual(await decryptFairExchange(offer, claim), plaintext);

const [incomingIndex, outgoingIndex] = await Promise.all([
  payeeGateway.payments(20),
  payerGateway.payments(20),
]);
assert.ok(incomingIndex.payments.some(payment =>
  payment.payment_hash === requirement.payment_hash && payment.status === "Paid"
));
assert.ok(outgoingIndex.payments.some(payment =>
  payment.payment_hash === requirement.payment_hash && payment.status === "Success"
));

privateKey.fill(0);

console.log(JSON.stringify({
  schema: "morph.payment_gateway_fiber_devnet_e2e",
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
      if (!(error instanceof MorphPaymentGatewayError) || error.status !== 402) throw error;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
  throw lastError;
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
