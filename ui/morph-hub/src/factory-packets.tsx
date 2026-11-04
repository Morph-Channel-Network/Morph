import { useState } from 'react';
import {
  inspectFactoryRequest,
  inspectFactorySignature,
  type FactoryRequest,
  type FactoryRequestInspection,
  type FactorySignatureReceipt,
} from '@morph-network/agent-sdk';

/** A public, offline review. Private child exits stay with the child, and
 * signer reservations and native submission stay in the Factory operator. */
export function FactoryPacketInspector() {
  const [requestText, setRequestText] = useState('');
  const [receiptText, setReceiptText] = useState('');
  const [inspection, setInspection] = useState<FactoryRequestInspection | null>(null);
  const [receiptChecked, setReceiptChecked] = useState(false);
  const [error, setError] = useState('');

  const inspect = () => {
    setInspection(null);
    setReceiptChecked(false);
    setError('');
    try {
      if (new TextEncoder().encode(requestText).length > 4 * 1024 * 1024) throw new Error('Public request exceeds the size limit.');
      const request = JSON.parse(requestText) as FactoryRequest;
      const review = inspectFactoryRequest(request);
      if (receiptText.trim()) {
        if (receiptText.length > 4096) throw new Error('Public receipt exceeds the size limit.');
        inspectFactorySignature(request, JSON.parse(receiptText) as FactorySignatureReceipt);
        setReceiptChecked(true);
      }
      setInspection(review);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  };

  return <section className="drawer-section" aria-label="Current Factory public packet inspection">
    <h2>Current Factory request</h2>
    <p className="inline-note">Inspect the public request produced by the native Factory operator. This review grants no signing or broadcast authority. Keep private child recovery packages in the child's private store.</p>
    <label>Public Factory request JSON
      <textarea data-testid="factory-request-json" value={requestText} onChange={event => { setRequestText(event.target.value); setInspection(null); }} rows={7} spellCheck={false} />
    </label>
    <label>Public participant signature receipt JSON (optional)
      <textarea data-testid="factory-signature-json" value={receiptText} onChange={event => { setReceiptText(event.target.value); setInspection(null); }} rows={3} spellCheck={false} />
    </label>
    <button type="button" onClick={inspect} disabled={!requestText.trim()}>Inspect public request</button>
    {error && <p role="alert" className="inline-error">{error}</p>}
    {inspection && <div data-testid="factory-packet-inspection">
      <h3>Public terms verified</h3>
      <p>Role: <code>{inspection.role}</code> · Required participants: {inspection.required_members.length} of {inspection.members.length}.</p>
      <p className="mono">Request: {inspection.request_id}<br />Transaction: {inspection.transaction_hash}<br />Signing digest: {inspection.signing_digest}</p>
      <p>{inspection.requires_activation ? 'The resulting Factory requires canonical activation.' : 'This request preserves the bound Factory custody context.'}</p>
      {receiptChecked && <p role="status">Participant receipt matches the exact request, role and required member.</p>}
      {inspection.missing_deliveries.length > 0 ? <div role="status">
        <strong>Child delivery incomplete: {inspection.missing_deliveries.length} attestation(s) missing.</strong>
        <p>The native signer requires every child recipient to retain a complete exit before parent signing.</p>
        <ul>{inspection.missing_deliveries.map(delivery => <li className="mono" key={`${delivery.child_index}:${delivery.pubkey}`}>Child {delivery.child_index}: {delivery.pubkey}</li>)}</ul>
      </div> : <p>All required child delivery attestations are present.</p>}
      {(['source', 'target'] as const).map(side => {
        const custody = inspection[side];
        return custody && <div key={side}>
          <h4>{side === 'source' ? 'Source custody' : 'Resulting custody'}</h4>
          <p>Update {custody.update_number} · State carrier {custody.state_carrier_capacity} shannons · {custody.vault_count} Vault(s)</p>
          <ul>{custody.assets.map(asset => <li key={asset.type_hash ?? 'ckb'} className="mono">{asset.type_hash ?? 'CKB'}: reserve {asset.reserve}; business CKB {asset.business_ckb}; token amount {asset.amount}</li>)}</ul>
        </div>;
      })}
      <h4>Committed rights</h4>
      <ul>{inspection.target_rights.map((right, index) => <li key={index} className="mono">{right.participant} · {right.kind} · {right.asset_type ?? 'CKB'} · {right.quantity}</li>)}</ul>
      {inspection.children.map(child => <div key={child.child_index}>
        <h4>Child {child.child_index}: initial exit</h4>
        <p>State {child.initial_exit.state_number} · {child.initial_exit.phase} · Carrier {child.initial_exit.state_carrier_capacity} shannons</p>
        <p className="mono">Funding context: {child.initial_exit.funding_context_id}</p>
        {child.initial_exit.capability.kind === 'ckb_conditional' ? <>
          <p>Pending CKB: {child.initial_exit.capability.pending_ckb} shannons</p>
          <ul>{child.initial_exit.capability.transfers.map(transfer => <li className="mono" key={transfer.transfer_id}>{transfer.amount} shannons · payer {transfer.payer_lock_hash} · payee {transfer.payee_lock_hash} · {transfer.hash_algorithm} {transfer.payment_hash} · refund block {transfer.refund_after_block}</li>)}</ul>
        </> : <p>Settlement: ordinary allocations.</p>}
      </div>)}
      <p className="inline-note">Native Core must verify complete Factory transition semantics. Canonical source cells, approved dependencies, VM execution and durable signer reservation must also pass before key use or submission. This browser view checks public terms and signatures.</p>
    </div>}
  </section>;
}
