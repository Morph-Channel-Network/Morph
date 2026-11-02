import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake2b } from "@noble/hashes/blake2.js";

import {
  createSignedPaymentPayload,
  deriveMorphAccountId,
  MorphAgentClient,
  MorphHubClient,
  inspectMultiAssetPackage,
  createMultiAssetProposal,
  inspectMultiAssetProposal,
  inspectMultiAssetProposalSignature,
  verifySignedPaymentPayload,
} from "../dist/index.js";

const multiAsset = JSON.parse(await readFile(new URL("./fixtures/multi-asset.json", import.meta.url), "utf8"));
const multiAssetSummary = JSON.parse(await readFile(new URL("./fixtures/multi-asset-summary.json", import.meta.url), "utf8"));
assert.deepEqual(inspectMultiAssetPackage(multiAsset), multiAssetSummary);
assert.equal(multiAssetSummary.assets[0].amount, ((1n << 127n) - 1n).toString());
assert.throws(() => inspectMultiAssetPackage({ ...multiAsset, state_carrier_capacity: "0100000000000" }), /carrier capacity/);
assert.throws(() => inspectMultiAssetPackage({ ...multiAsset, witness_hex: `${multiAsset.witness_hex}00` }), /truncated recovery evidence/);
assert.throws(() => inspectMultiAssetPackage({ ...multiAsset, cell_deps: [] }), /incomplete code dependencies/);
assert.throws(() => inspectMultiAssetPackage({ ...multiAsset, cell_deps: [...multiAsset.cell_deps, multiAsset.cell_deps[0]] }), /duplicate or unordered code dependencies/);
const badSignature = Buffer.from(multiAsset.signature_witness_hex.slice(2), "hex");
badSignature[40] ^= 1;
assert.throws(() => inspectMultiAssetPackage({ ...multiAsset, signature_witness_hex: `0x${badSignature.toString("hex")}` }), /signature/);

// Re-sign a descriptor that burns type B to mint type A. Signature validity
// must never replace separate conservation for the two xUDT domains.
const forged = { ...multiAsset };
const forgedHeader = Buffer.from(forged.header_hex.slice(2), "hex");
const forgedWitness = Buffer.from(forged.witness_hex.slice(2), "hex");
const descriptorStart = 28 + forgedWitness.readUInt32LE(12);
const descriptorLength = forgedWitness.readUInt32LE(16);
for (const [assetIndex, delta] of [[0, 1n], [1, -1n]]) {
  const offset = descriptorStart + 100 + assetIndex * 97 + 33 + 16;
  const amount = forgedWitness.readBigUInt64LE(offset) + (forgedWitness.readBigUInt64LE(offset + 8) << 64n) + delta;
  forgedWitness.writeBigUInt64LE(amount & ((1n << 64n) - 1n), offset);
  forgedWitness.writeBigUInt64LE(amount >> 64n, offset + 8);
}
const ckbHash = (...parts) => blake2b(Buffer.concat(parts.map((part) => Buffer.from(part))), {
  dkLen: 32, personalization: Buffer.from("ckb-default-hash"),
});
forgedHeader.set(ckbHash(Buffer.from("CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1"), forgedWitness.subarray(descriptorStart, descriptorStart + descriptorLength)), 182);
const forgedDigest = ckbHash(Buffer.from("CKB_MORPH_MULTI_ASSET_STATE_V1"), forgedHeader);
const fixtureKeys = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)]
  .sort((a, b) => Buffer.compare(Buffer.from(secp256k1.getPublicKey(a, true)), Buffer.from(secp256k1.getPublicKey(b, true))));
const forgedSignatures = Buffer.from(multiAsset.signature_witness_hex.slice(2), "hex");
fixtureKeys.forEach((key, index) => {
  const signature = secp256k1.sign(forgedDigest, key, { prehash: false, format: "compact" });
  assert.equal(secp256k1.verify(signature, forgedDigest, secp256k1.getPublicKey(key, true), { prehash: false, format: "compact" }), true);
  forgedSignatures.set(signature, 37 + index * 97);
});
forged.header_hex = `0x${forgedHeader.toString("hex")}`;
forged.witness_hex = `0x${forgedWitness.toString("hex")}`;
forged.signature_witness_hex = `0x${forgedSignatures.toString("hex")}`;
assert.throws(() => inspectMultiAssetPackage(forged), /per-asset conservation mismatch/);

const largeState = { ...multiAsset };
const largeHeader = Buffer.from(largeState.header_hex.slice(2), "hex");
largeHeader.writeBigUInt64LE((1n << 64n) - 1n, 108);
const largeDigest = ckbHash(Buffer.from("CKB_MORPH_MULTI_ASSET_STATE_V1"), largeHeader);
const largeSignatures = Buffer.from(multiAsset.signature_witness_hex.slice(2), "hex");
fixtureKeys.forEach((key, index) => largeSignatures.set(secp256k1.sign(largeDigest, key, { prehash: false, format: "compact" }), 37 + index * 97));
largeState.header_hex = `0x${largeHeader.toString("hex")}`;
largeState.signature_witness_hex = `0x${largeSignatures.toString("hex")}`;
assert.equal(inspectMultiAssetPackage(largeState).state_number, ((1n << 64n) - 1n).toString());

const updateFixture = JSON.parse(await readFile(new URL("./fixtures/multi-asset-update.json", import.meta.url), "utf8"));
const proposal = createMultiAssetProposal(multiAsset, updateFixture.proposal.state_number, updateFixture.proposal.descriptor_hex);
assert.deepEqual(proposal, updateFixture.proposal);
const proposalView = inspectMultiAssetProposal(multiAsset, proposal);
assert.equal(proposalView.summary.package_id, proposal.signing_digest);
assert.equal(BigInt(proposalView.payouts[0].allocations[0].amount) + BigInt(proposalView.payouts[0].allocations[1].amount), BigInt(multiAssetSummary.assets[0].amount));
assert.deepEqual(inspectMultiAssetProposalSignature(multiAsset, proposal, updateFixture.signature), {
  signer_pubkey: updateFixture.signature.pubkey, signing_digest: proposal.signing_digest,
});
assert.throws(() => inspectMultiAssetProposal(multiAsset, {...proposal, base_state_digest: `0x${"00".repeat(32)}`}), /current signed state/);
assert.throws(() => inspectMultiAssetProposal(multiAsset, {...proposal, signing_digest: `0x${"00".repeat(32)}`}), /signing digest mismatch/);
assert.throws(() => inspectMultiAssetProposal(multiAsset, {...proposal, state_number: multiAssetSummary.state_number}), /advance state number/);
assert.throws(() => inspectMultiAssetProposal(multiAsset, {...proposal, extra: true}), /proposal fields/);
assert.throws(() => inspectMultiAssetProposalSignature(multiAsset, proposal, {...updateFixture.signature, signature:`0x${"00".repeat(64)}`}), /signature/);
assert.throws(() => inspectMultiAssetProposalSignature(multiAsset, proposal, {...updateFixture.signature, signing_digest:multiAssetSummary.package_id}), /context or signer mismatch/);
assert.throws(() => createMultiAssetProposal(multiAsset, proposal.state_number, `0x${forgedWitness.subarray(descriptorStart, descriptorStart + descriptorLength).toString("hex")}`), /per-asset conservation mismatch/);
assert.throws(() => createMultiAssetProposal({...multiAsset, signature_witness_hex:`0x${badSignature.toString("hex")}`}, proposal.state_number, proposal.descriptor_hex), /signature/);
const maximumProposal = createMultiAssetProposal(multiAsset, ((1n<<64n)-1n).toString(), proposal.descriptor_hex);
assert.equal(inspectMultiAssetProposal(multiAsset, maximumProposal).summary.state_number, ((1n<<64n)-1n).toString());
assert.throws(() => createMultiAssetProposal(multiAsset, (1n<<64n).toString(), proposal.descriptor_hex), /overflow/);

const requirements = {
  requirement_id: `0x${"11".repeat(32)}`,
  payment_hash: `0x${"22".repeat(32)}`,
  payer: "0xc3884ddf5c0e66af9bd067147e948641917a9fd9df768dc299172e35a613a6e8",
  payee: `0x${"99".repeat(32)}`,
};
const payload = createSignedPaymentPayload(
  requirements,
  `0x${"07".repeat(32)}`,
);

assert.equal(
  payload.payer_pubkey_sec1,
  "0x02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
);
assert.equal(
  payload.payer,
  "0xc3884ddf5c0e66af9bd067147e948641917a9fd9df768dc299172e35a613a6e8",
);
assert.equal(
  deriveMorphAccountId(Buffer.from(payload.payer_pubkey_sec1.slice(2), "hex")),
  payload.payer,
);
assert.equal(verifySignedPaymentPayload(requirements, payload), true);
assert.equal(
  verifySignedPaymentPayload(
    { ...requirements, payment_hash: `0x${"23".repeat(32)}` },
    payload,
  ),
  false,
);

assert.throws(
  () => new MorphAgentClient("http://agent.example.com"),
  /must use HTTPS/,
);
assert.doesNotThrow(() => new MorphAgentClient("http://127.4.3.2:4617"));
assert.doesNotThrow(() => new MorphHubClient("http://127.0.0.1:4617"));
assert.throws(
  () => new MorphHubClient("http://hub.example.com"),
  /must use HTTPS/,
);

const apiBearerToken = "m".repeat(32);
const originalFetch = globalThis.fetch;
globalThis.fetch = async (_url, init) => {
  assert.equal(init.headers.authorization, `Bearer ${apiBearerToken}`);
  return new Response(JSON.stringify({ network: "morph-ckb" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
try {
  const client = new MorphAgentClient("https://agent.example.com", { apiBearerToken });
  assert.deepEqual(await client.supported(), { network: "morph-ckb" });
} finally {
  globalThis.fetch = originalFetch;
}

globalThis.fetch = async (url, init) => {
  assert.equal(init.headers.authorization, `Bearer ${apiBearerToken}`);
  assert.equal(new URL(url).search, "");
  if (init.method === "POST") {
    assert.equal(new URL(url).pathname, "/api/multi-asset-packages");
    assert.deepEqual(JSON.parse(init.body), multiAsset);
    return new Response(JSON.stringify({ multi_asset_package_count: 1 }), { status: 200 });
  }
  assert.equal(new URL(url).pathname, `/api/multi-asset-packages/${multiAssetSummary.package_id}`);
  return new Response(JSON.stringify(multiAsset), { status: 200 });
};
try {
  const client = new MorphHubClient("https://hub.example.com", apiBearerToken);
  assert.deepEqual(await client.importMultiAssetPackage(multiAsset), { multi_asset_package_count: 1 });
  assert.deepEqual(await client.multiAssetPackage(multiAssetSummary.package_id), multiAsset);
} finally {
  globalThis.fetch = originalFetch;
}

globalThis.fetch = async () => new Response(
  new Uint8Array(2 * 1024 * 1024 + 1),
  { status: 200 },
);
try {
  const client = new MorphAgentClient("https://agent.example.com");
  await assert.rejects(
    client.supported(),
    /response exceeds the maximum size/,
  );
} finally {
  globalThis.fetch = originalFetch;
}
