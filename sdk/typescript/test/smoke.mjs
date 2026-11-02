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
  inspectMultiAssetRootDraft,
  inspectMultiAssetFundingSignature,
  assembleMultiAssetRootFunding,
  inspectMultiAssetRootFunding,
  inspectMultiAssetRootCollection,
  inspectMultiAssetSpliceDraft,
  inspectMultiAssetSpliceSignature,
  assembleMultiAssetSpliceFunding,
  inspectMultiAssetSpliceFunding,
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

const rootFixture = JSON.parse(await readFile(new URL("./fixtures/multi-asset-root.json", import.meta.url), "utf8"));
assert.deepEqual(inspectMultiAssetRootDraft(rootFixture.draft), rootFixture.inspection);
for (const [target, receipts] of [["exit", rootFixture.exit_receipts], ["creation", rootFixture.creation_receipts]]) {
  for (const receipt of receipts) assert.deepEqual(inspectMultiAssetFundingSignature(rootFixture.draft, target, receipt), {signer_pubkey: receipt.pubkey, signing_digest: receipt.signing_digest});
}
const assembledRoot = assembleMultiAssetRootFunding(rootFixture.draft, rootFixture.exit_receipts, rootFixture.creation_receipts);
assert.deepEqual(assembledRoot, rootFixture.funding);
assert.deepEqual(inspectMultiAssetRootFunding(assembledRoot), rootFixture.inspection);
assert.throws(() => assembleMultiAssetRootFunding(rootFixture.draft, [rootFixture.exit_receipts[0]], rootFixture.creation_receipts), /both participant/);
assert.throws(() => assembleMultiAssetRootFunding(rootFixture.draft, [rootFixture.exit_receipts[0],rootFixture.exit_receipts[0]], rootFixture.creation_receipts), /duplicate/);
assert.throws(() => inspectMultiAssetFundingSignature(rootFixture.draft, "creation", rootFixture.exit_receipts[0]), /context/);
assert.throws(() => inspectMultiAssetRootDraft({...rootFixture.draft,participants:[...rootFixture.draft.participants].reverse()}), /participants/);
assert.throws(() => inspectMultiAssetRootDraft({...rootFixture.draft,extra:true}), /draft fields/);
assert.throws(() => inspectMultiAssetRootDraft({...rootFixture.draft,transaction_hex:assembledRoot.transaction_hex}), /contains creation/);
assert.throws(() => inspectMultiAssetFundingSignature(rootFixture.draft,"exit",{...rootFixture.exit_receipts[0],signature:`0x${"00".repeat(64)}`}), /signature/);

assert.equal(inspectMultiAssetRootCollection(rootFixture.collection).ready_to_export, true);
assert.throws(() => inspectMultiAssetRootCollection({...rootFixture.collection,exit_signatures:[]}), /complete initial exit/);
assert.throws(() => inspectMultiAssetRootCollection({...rootFixture.collection,exit_signatures:[...rootFixture.exit_receipts].reverse()}), /unique and ordered/);

// Preserve State and custody commitments while repricing only the external
// change: both root signing domains must still change with the raw TX hash.
function fieldSlices(raw) {
  const total=raw.readUInt32LE(0);assert.equal(total,raw.length);
  const first=raw.readUInt32LE(4);const count=first/4-1;
  return Array.from({length:count},(_,i)=>raw.subarray(raw.readUInt32LE(4+4*i),i+1===count?raw.length:raw.readUInt32LE(8+4*i)));
}
function packedTable(fields) {
  const header=Buffer.alloc(4*(fields.length+1));let offset=header.length;
  fields.forEach((field,i)=>{header.writeUInt32LE(offset,4+4*i);offset+=field.length;});header.writeUInt32LE(offset,0);
  return Buffer.concat([header,...fields]);
}
function changeRoot(rawHex, mutate) {
  const transaction=fieldSlices(Buffer.from(rawHex.slice(2),'hex'));const body=fieldSlices(transaction[0]).map(field=>Buffer.from(field));
  mutate(body);transaction[0]=packedTable(body);return `0x${packedTable(transaction).toString('hex')}`;
}
const repriced=changeRoot(rootFixture.draft.transaction_hex, body=>{
  const outputs=fieldSlices(body[4]);const change=fieldSlices(outputs[0]).map(field=>Buffer.from(field));
  change[0].writeBigUInt64LE(change[0].readBigUInt64LE()+1n);outputs[0]=packedTable(change);body[4]=packedTable(outputs);
});
const repricedDraft={...rootFixture.draft,transaction_hex:repriced};
const repricedInspection=inspectMultiAssetRootDraft(repricedDraft);
assert.notEqual(repricedInspection.creation_digest,rootFixture.inspection.creation_digest);
assert.notEqual(repricedInspection.exit_digest,rootFixture.inspection.exit_digest);
assert.throws(()=>assembleMultiAssetRootFunding(repricedDraft,rootFixture.exit_receipts,rootFixture.creation_receipts),/context/);
const repricedSigned=changeRoot(assembledRoot.transaction_hex, body=>{
  const outputs=fieldSlices(body[4]);const change=fieldSlices(outputs[0]).map(field=>Buffer.from(field));
  change[0].writeBigUInt64LE(change[0].readBigUInt64LE()+1n);outputs[0]=packedTable(change);body[4]=packedTable(outputs);
});
assert.throws(()=>inspectMultiAssetRootFunding({...assembledRoot,transaction_hex:repricedSigned}),/signature/);
const wrongVault=changeRoot(rootFixture.draft.transaction_hex, body=>{
  const outputs=fieldSlices(body[4]);const vault=fieldSlices(outputs[2]).map(field=>Buffer.from(field));
  vault[0].writeBigUInt64LE(vault[0].readBigUInt64LE()-1n);outputs[2]=packedTable(vault);body[4]=packedTable(outputs);
});
assert.throws(()=>inspectMultiAssetRootDraft({...rootFixture.draft,transaction_hex:wrongVault}),/physical value/);
const movedState=changeRoot(rootFixture.draft.transaction_hex, body=>{
  const outputs=fieldSlices(body[4]);const data=fieldSlices(body[5]);[outputs[0],outputs[1]]=[outputs[1],outputs[0]];[data[0],data[1]]=[data[1],data[0]];
  body[4]=packedTable(outputs);body[5]=packedTable(data);
});
assert.throws(()=>inspectMultiAssetRootDraft({...rootFixture.draft,transaction_hex:movedState}),/anchor/);
const duplicateDep=changeRoot(rootFixture.draft.transaction_hex, body=>body[1].set(body[1].subarray(4,41),41));
assert.throws(()=>inspectMultiAssetRootDraft({...rootFixture.draft,transaction_hex:duplicateDep}),/duplicate or unordered/);
const duplicateInput=changeRoot(rootFixture.draft.transaction_hex, body=>{
  const item=body[3].subarray(4);const count=Buffer.alloc(4);count.writeUInt32LE(2);body[3]=Buffer.concat([count,item,item]);
});
assert.throws(()=>inspectMultiAssetRootDraft({...rootFixture.draft,transaction_hex:duplicateInput}),/duplicate or invalid funding input/);
const zeroExit={...multiAsset};const zeroHeader=Buffer.from(zeroExit.header_hex.slice(2),'hex');zeroHeader.writeBigUInt64LE(0n,108);zeroExit.header_hex=`0x${zeroHeader.toString('hex')}`;
assert.throws(()=>inspectMultiAssetPackage(zeroExit),/positive state number/);

const spliceFixture = JSON.parse(await readFile(new URL("./fixtures/multi-asset-splice.json", import.meta.url), "utf8"));
const spliceInfo=inspectMultiAssetSpliceDraft(spliceFixture.current,spliceFixture.draft);
for(const target of ["creation","recovery","bridge"]) {
  assert.equal(spliceInfo[`${target}_digest`],spliceFixture[`${target}_digest`]);
  for(const receipt of spliceFixture[`${target}_receipts`])assert.equal(inspectMultiAssetSpliceSignature(spliceFixture.current,spliceFixture.draft,`splice-${target}`,receipt).signer_pubkey,receipt.pubkey);
}
assert.equal(spliceInfo.assets.length,2);
assert.equal(spliceInfo.assets[0].amount,((1n<<127n)-1n).toString());
assert.deepEqual(spliceInfo.flows.map(flow=>flow.deposit.amount),["0","0"]);
const spliceAssembled=assembleMultiAssetSpliceFunding(spliceFixture.current,spliceFixture.draft,spliceFixture.recovery_receipts,spliceFixture.creation_receipts,spliceFixture.bridge_receipts);
assert.deepEqual(spliceAssembled,spliceFixture.funding);
assert.deepEqual(inspectMultiAssetSpliceFunding(spliceFixture.current,spliceAssembled),spliceInfo);
assert.equal(spliceInfo.new_funding_context_id,inspectMultiAssetPackage(spliceAssembled.recovery_package).funding_context_id);
assert.equal(inspectMultiAssetPackage(spliceAssembled.recovery_package).package_id,spliceInfo.recovery_digest);
assert.throws(()=>assembleMultiAssetSpliceFunding(spliceFixture.current,spliceFixture.draft,[],spliceFixture.creation_receipts,spliceFixture.bridge_receipts),/both participant/);
assert.throws(()=>assembleMultiAssetSpliceFunding(spliceFixture.current,spliceFixture.draft,spliceFixture.recovery_receipts,spliceFixture.creation_receipts,[spliceFixture.bridge_receipts[0],spliceFixture.bridge_receipts[0]]),/duplicate/);
assert.throws(()=>inspectMultiAssetSpliceSignature(spliceFixture.current,spliceFixture.draft,"splice-bridge",spliceFixture.creation_receipts[0]),/context/);
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,extra:true}),/base state/);
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,base_state_digest:`0x${"00".repeat(32)}`}),/base state/);
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,transaction_hex:spliceAssembled.transaction_hex}),/Morph witness/);
const swappedOldVaults=changeRoot(spliceFixture.draft.transaction_hex,body=>{
 const first=Buffer.from(body[3].subarray(48,92));const second=Buffer.from(body[3].subarray(92,136));body[3].set(second,48);body[3].set(first,92);
});
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,transaction_hex:swappedOldVaults}),/Vault order/);
const changedSpliceVault=changeRoot(spliceFixture.draft.transaction_hex,body=>{
 const outputs=fieldSlices(body[4]);const vault=fieldSlices(outputs[1]).map(field=>Buffer.from(field));vault[0].writeBigUInt64LE(vault[0].readBigUInt64LE()+1n);outputs[1]=packedTable(vault);body[4]=packedTable(outputs);
});
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,transaction_hex:changedSpliceVault}),/physical output/);
const changedSpliceFlow=Buffer.from(spliceFixture.draft.flows_hex.slice(2),'hex');changedSpliceFlow[37]=1;
assert.throws(()=>inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,flows_hex:`0x${changedSpliceFlow.toString('hex')}`}),/conservation/);
const changedSpliceDep=changeRoot(spliceFixture.draft.transaction_hex,body=>{body[1][4]^=1;});
const changedSplice={...spliceFixture.draft,transaction_hex:changedSpliceDep};
const changedSpliceInfo=inspectMultiAssetSpliceDraft(spliceFixture.current,changedSplice);
assert.equal(changedSpliceInfo.creation_digest,spliceInfo.creation_digest);
assert.notEqual(changedSpliceInfo.recovery_digest,spliceInfo.recovery_digest);
assert.notEqual(changedSpliceInfo.bridge_digest,spliceInfo.bridge_digest);
assert.throws(()=>assembleMultiAssetSpliceFunding(spliceFixture.current,changedSplice,spliceFixture.recovery_receipts,spliceFixture.creation_receipts,spliceFixture.bridge_receipts),/context/);

// A top-up is a delta into an already funded Vault, so its token amount
// can be positive with zero deposited reserve and business capacity.
const topupWitness=Buffer.from(spliceFixture.draft.new_witness_hex.slice(2),'hex');
const topupManifestEnd=28+topupWitness.readUInt32LE(12);
const topupDescriptorEnd=topupManifestEnd+topupWitness.readUInt32LE(16);
const read128=(raw,offset)=>raw.readBigUInt64LE(offset)+(raw.readBigUInt64LE(offset+8)<<64n);
const write128=(raw,offset,value)=>{raw.writeBigUInt64LE(value&((1n<<64n)-1n),offset);raw.writeBigUInt64LE(value>>64n,offset+8);};
const topupAmount=read128(topupWitness,28+4+65+16)+1n;
write128(topupWitness,28+4+65+16,topupAmount);
const topupPayout=topupManifestEnd+100+33+16;write128(topupWitness,topupPayout,read128(topupWitness,topupPayout)+1n);
const topupFlows=Buffer.from(spliceFixture.draft.flows_hex.slice(2),'hex');write128(topupFlows,4+33+16,1n);
const topupTransaction=changeRoot(spliceFixture.draft.transaction_hex,body=>{
 const data=fieldSlices(body[5]).map(field=>Buffer.from(field));const header=data[0].subarray(4);
 header.set(ckbHash(Buffer.from("CKB_MORPH_MULTI_ASSET_VAULT_SET_V1"),topupWitness.subarray(28,topupManifestEnd)),250);
 header.set(ckbHash(Buffer.from("CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1"),topupWitness.subarray(topupManifestEnd,topupDescriptorEnd)),182);
 write128(data[1],4,topupAmount);body[5]=packedTable(data);
});
const topupInfo=inspectMultiAssetSpliceDraft(spliceFixture.current,{...spliceFixture.draft,transaction_hex:topupTransaction,new_witness_hex:`0x${topupWitness.toString('hex')}`,flows_hex:`0x${topupFlows.toString('hex')}`});
assert.deepEqual(topupInfo.flows[0].deposit,{reserve:"0",business_ckb:"0",amount:"1"});
assert.equal(topupInfo.assets[0].amount,topupAmount.toString());

const spliceTransitions = JSON.parse(await readFile(new URL("./fixtures/multi-asset-splice-transitions.json", import.meta.url), "utf8"));
for(const transition of spliceTransitions) {
 const info=inspectMultiAssetSpliceDraft(transition.current,transition.draft);
 const assembled=assembleMultiAssetSpliceFunding(transition.current,transition.draft,transition.recovery_receipts,transition.creation_receipts,transition.bridge_receipts);
 assert.deepEqual(assembled,transition.funding);
 assert.deepEqual(inspectMultiAssetSpliceFunding(transition.current,assembled),info);
 assert.equal(info.new_funding_context_id,inspectMultiAssetPackage(assembled.recovery_package).funding_context_id);
 assert.notEqual(info.new_funding_context_id,info.old_funding_context_id);
 assert.equal(info.assets.length,transition.name==="remove"?1:2);
 assert.ok(info.flows.some(flow=>BigInt((transition.name==="remove"?flow.withdrawal:flow.deposit).amount)>0n));
 const damaged=Buffer.from(assembled.transaction_hex.slice(2),'hex');damaged[damaged.length-1]^=1;
 assert.throws(()=>inspectMultiAssetSpliceFunding(transition.current,{...assembled,transaction_hex:`0x${damaged.toString('hex')}`}));
 assert.throws(()=>inspectMultiAssetSpliceFunding(transition.current,{...assembled,recovery_package:transition.current}));
}

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

const rootCalls=[];
let rootReply=rootFixture.collection;
globalThis.fetch=async(url,init)=>{
  assert.equal(init.headers.authorization,`Bearer ${apiBearerToken}`);assert.equal(new URL(url).search,'');
  rootCalls.push({path:new URL(url).pathname,method:init.method,body:init.body===undefined?undefined:JSON.parse(init.body)});
  if(init.method==='POST')return new Response(JSON.stringify({root_fundings:[]}),{status:200});
  return new Response(JSON.stringify(new URL(url).pathname.endsWith('/export')?rootFixture.funding:rootReply),{status:200});
};
try {
  const client=new MorphHubClient('https://hub.example.com',apiBearerToken);const id=rootFixture.inspection.transaction_hash;
  await client.importRootFunding(rootFixture.draft);assert.deepEqual(rootCalls.at(-1).body,rootFixture.draft);
  assert.deepEqual(await client.rootFunding(id),rootFixture.collection);
  await client.addRootFundingSignature(id,'creation',rootFixture.creation_receipts[0]);assert.equal(rootCalls.at(-1).path,`/api/root-fundings/${id}/signatures`);
  assert.deepEqual(await client.exportRootFunding(id),rootFixture.funding);
  rootReply={...rootFixture.collection,exit_signatures:[],creation_signatures:[]};const before=rootCalls.filter(call=>call.method==='POST').length;
  await assert.rejects(client.addRootFundingSignature(id,'creation',rootFixture.creation_receipts[0]),/complete initial exit/);
  assert.equal(rootCalls.filter(call=>call.method==='POST').length,before);
  await assert.rejects(client.rootFunding(`0x${'00'.repeat(32)}`),/different root/);
} finally {globalThis.fetch=originalFetch;}

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
