import { Activity, BadgeCheck, Factory, FileJson, GitBranch, Network, Plus, RadioTower, ReceiptText, RefreshCw, Split, Upload, Users } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useEffect, useMemo, useState } from 'react';
import { connectPeer, getMultiAssetRecoveryPackage, getStateFile, postAction, previewStateFile, replaceStateFile, type RestorePreview } from './api';
import { ConfirmActionDialog, ValidatedInput, ValidatedTextarea } from './components';
import {
  Asset,
  ChannelRecord,
  FactoryRecord,
  Hex32,
  NodeState,
  PeerRecord,
  Pubkey,
  assertHex32,
  assertIncludesPubkey,
  assertInvoiceAmount,
  assertNonNegativeInteger,
  assertPositiveInteger,
  assertRemotePubkey,
  assetLabel,
  formatAmount,
  hasHubScope,
  normaliseAsset,
  parsePubkeyList,
  shortHex,
} from './domain';
import {
  copyTextToClipboard,
  newestInvoice,
  randomHex32,
  requiredText,
  sortChannelsForOperator,
  sortFactoriesForOperator,
  sortInvoicesNewestFirst,
  uniqueStrings,
} from './state';

type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;
type ChannelActionTab = 'open' | 'splice' | 'publish' | 'finalise';
type FactoryActionTab = 'open' | 'advance' | 'materialise';
type FactoryActionTarget = {
  factoryId: Hex32;
  intent: 'advance' | 'materialise';
  nonce: number;
};
type ChannelFormMode = 'open' | 'materialise';
type ChannelFormDraft = {
  channelId: string;
  counterpartyPubkey: string;
  counterpartyAlias: string;
  fundingContextId: string;
  local: string;
  remote: string;
  pending: string;
  sponsorBudget: string;
  asset: Asset;
};
type ChannelFormPrefill = {
  nonce: number;
  draft: Partial<ChannelFormDraft>;
};

const DEFAULT_INVOICE_EXPIRY_SECS = '3600';
const DEFAULT_PENDING_CAPACITY = '0';
const DEFAULT_SPONSOR_BUDGET = '1000000';
const MAX_PEER_ALIAS_LEN = 80;

const invoiceExpiryPresets = [
  { label: '1h', value: '3600' },
  { label: '6h', value: '21600' },
  { label: '24h', value: '86400' },
  { label: '7d', value: '604800' },
];

export function PeerActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [pubkey, setPubkey] = useState('');
  const [alias, setAlias] = useState('');
  const canWrite = hasHubScope(state.security, 'write');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Connect peer', () => connectPeer(assertRemotePubkey(pubkey, state.pubkey, 'Peer pubkey'), requiredText(alias, 'Alias')));
  };

  return (
    <div className="drawer-section">
      <h2>Peer Layer</h2>
      <form onSubmit={submit} className="form-grid">
        <ValidatedInput label="Peer pubkey" className="mono" testId="peer-pubkey" value={pubkey} onChange={setPubkey} validate={value => { assertRemotePubkey(value, state.pubkey, 'Peer pubkey'); }} />
        <ValidatedInput label="Alias" testId="peer-alias" value={alias} onChange={setAlias} maxLength={MAX_PEER_ALIAS_LEN} validate={value => { requiredText(value, 'Alias'); }} />
        <button data-testid="peer-connect" disabled={busy || !canWrite}><Users size={15} /> Connect peer</button>
        {!canWrite && <small className="inline-error">The current API token needs the write scope.</small>}
      </form>

      <div className="form-section">
        <h3>Known peers ({state.peers.length})</h3>
        <div className="stack-list">
          {state.peers.length === 0 && <div className="empty">No peers connected</div>}
          {state.peers.map(peer => (
            <div className="list-row" key={peer.node_id}>
              <div>
                <strong>{peer.alias}</strong>
                <small>{shortHex(peer.pubkey)}</small>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AssetSelect({ value, onChange }: { value: Asset; onChange: (asset: Asset) => void }) {
  const isXudt = value.kind === 'xudt';
  const typeHash = !isXudt ? '' : value.type_hash ?? '';
  const selectAsset = (kind: 'ckb' | 'xudt') => {
    onChange(kind === 'ckb' ? { kind: 'ckb' } : { kind: 'xudt', type_hash: typeHash ? (typeHash as Hex32) : undefined });
  };
  const updateHash = (raw: string) => {
    onChange({ kind: 'xudt', type_hash: (raw || undefined) as Hex32 | undefined });
  };
  return (
    <>
      <label>Asset
        <select value={value.kind} onChange={event => selectAsset(event.target.value as 'ckb' | 'xudt')}>
          <option value="ckb">CKB</option>
          <option value="xudt">xUDT</option>
        </select>
      </label>
      {isXudt && (
        <ValidatedInput label="Type hash" className="mono" value={typeHash} onChange={updateHash} validate={value => { assertHex32(value, 'Type hash'); }} />
      )}
    </>
  );
}

export function InvoiceActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [amount, setAmount] = useState('');
  const [description, setDescription] = useState('');
  const [expirySecs, setExpirySecs] = useState(DEFAULT_INVOICE_EXPIRY_SECS);
  const [paymentMode, setPaymentMode] = useState<'preimage' | 'hash'>('preimage');
  const [paymentSecret, setPaymentSecret] = useState(createDraftHex32);
  const [channelId, setChannelId] = useState('');
  const [asset, setAsset] = useState<Asset>({ kind: 'ckb' });
  const [decodeText, setDecodeText] = useState('');
  const [settleInvoiceId, setSettleInvoiceId] = useState('');
  const [settlePreimage, setSettlePreimage] = useState('');
  const [copyStatus, setCopyStatus] = useState('');
  const activeChannels = sortChannelsForOperator(state.channels, state.events).filter(channel => channel.phase === 'active');
  const latestActiveChannel = activeChannels[0];
  const canWrite = hasHubScope(state.security, 'write');
  const canSign = hasHubScope(state.security, 'sign');
  const canCreateInvoices = state.security.invoice_signing_enabled && canSign;
  const settleableInvoices = sortInvoicesNewestFirst(state.invoices.filter(invoice => invoice.status === 'open' || invoice.status === 'received'));
  const latestSettleableInvoice = newestInvoice(
    settleableInvoices
  );
  const maxInvoiceExpirySecs = state.security.max_invoice_expiry_secs || 604800;

  useEffect(() => {
    if (!channelId && latestActiveChannel) {
      setChannelId(latestActiveChannel.channel_id);
    }
  }, [channelId, latestActiveChannel]);

  useEffect(() => {
    if (paymentMode === 'preimage' && !paymentSecret) {
      setPaymentSecret(createDraftHex32());
    }
  }, [paymentMode, paymentSecret]);

  useEffect(() => {
    if (!settleInvoiceId && latestSettleableInvoice) {
      setSettleInvoiceId(latestSettleableInvoice.invoice_id);
    }
  }, [settleInvoiceId, latestSettleableInvoice]);

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    if (!canCreateInvoices) return;
    void runAction('Create invoice', async () => {
      const expiry = Number(assertPositiveInteger(expirySecs, 'Expiry seconds'));
      if (expiry > maxInvoiceExpirySecs) {
        throw new Error(`Expiry seconds must be at most ${maxInvoiceExpirySecs}.`);
      }
      const body = {
        amount: assertInvoiceAmount(amount, asset),
        description: requiredText(description, 'Description'),
        expiry_secs: expiry,
        channel_id: channelId.trim() ? assertHex32(channelId, 'Channel id') : undefined,
        payment_preimage: paymentMode === 'preimage' ? assertHex32(paymentSecret, 'Payment preimage') : undefined,
        payment_hash: paymentMode === 'hash' ? assertHex32(paymentSecret, 'Payment hash') : undefined,
        asset: normaliseAsset(asset),
      };
      return postAction('/api/invoices', body);
    });
  };

  const submitDecode = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    const encodedInvoice = requiredText(decodeText, 'Encoded invoice');
    void runAction('Receive invoice', async () => {
      const previousInvoiceIds = new Set(state.invoices.map(invoice => invoice.invoice_id));
      const decodedState = await postAction('/api/invoices/decode', { encoded_invoice: encodedInvoice });
      const decodedInvoice = newestInvoice(decodedState.invoices.filter(invoice => !previousInvoiceIds.has(invoice.invoice_id) || invoice.encoded_invoice === encodedInvoice));
      if (decodedInvoice?.status === 'open') {
        return postAction(`/api/invoices/${decodedInvoice.invoice_id}/receive`);
      }
      return decodedState;
    });
  };

  const submitSettle = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Settle invoice', () => {
      const invoiceId = assertHex32(settleInvoiceId, 'Invoice id');
      const paymentPreimage = assertHex32(settlePreimage, 'Payment preimage');
      return postAction(`/api/invoices/${invoiceId}/settle`, { payment_preimage: paymentPreimage });
    });
  };

  const copyLatestInvoice = async () => {
    const encodedInvoice = latestSettleableInvoice?.encoded_invoice;
    if (!encodedInvoice) return;
    setCopyStatus('');
    try {
      await copyTextToClipboard(encodedInvoice);
      setCopyStatus('copied');
    } catch (err) {
      setCopyStatus(String((err as Error).message));
    }
  };

  return (
    <div className="drawer-section">
      <h2>Invoice Layer</h2>
      <form onSubmit={submitCreate} className="form-grid">
        <ValidatedInput label="Amount" className="mono" testId="invoice-amount" value={amount} onChange={setAmount} validate={value => { assertInvoiceAmount(value, asset); }} />
        <label>Description<input data-testid="invoice-description" value={description} onChange={event => setDescription(event.target.value)} /></label>
        <ValidatedInput
          label={(
            <span className="field-label-row">
            Expiry seconds
              <span className="quick-picks">
                {invoiceExpiryPresets.map(preset => (
                  <button type="button" className="field-action" key={preset.value} onClick={() => setExpirySecs(preset.value)}>
                    {preset.label}
                  </button>
                ))}
              </span>
            </span>
          )}
          className="mono"
          testId="invoice-expiry-secs"
          value={expirySecs}
          onChange={setExpirySecs}
          validate={value => {
            const expiry = Number(assertPositiveInteger(value, 'Expiry seconds'));
            if (expiry > maxInvoiceExpirySecs) throw new Error(`Expiry seconds must be at most ${maxInvoiceExpirySecs}.`);
          }}
        />
        <label>Payment input
          <select data-testid="invoice-payment-mode" value={paymentMode} onChange={event => setPaymentMode(event.target.value as 'preimage' | 'hash')}>
            <option value="preimage">preimage</option>
            <option value="hash">hash</option>
          </select>
        </label>
        <ValidatedInput
          label={(
            <span className="field-label-row">
              {paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'}
              {paymentMode === 'preimage' && (
                <button type="button" className="field-action" data-testid="invoice-generate-payment-secret" onClick={() => setPaymentSecret(randomHex32())}>
                  <RefreshCw size={12} /> Generate
                </button>
              )}
            </span>
          )}
          className="mono"
          testId="invoice-payment-secret"
          value={paymentSecret}
          onChange={setPaymentSecret}
          validate={value => { assertHex32(value, paymentMode === 'preimage' ? 'Payment preimage' : 'Payment hash'); }}
        />
        <ValidatedInput
          label={(
            <span className="field-label-row">
              Channel id
              <button
                type="button"
                className="field-action"
                data-testid="invoice-use-active-channel"
                onClick={() => setChannelId(latestActiveChannel?.channel_id ?? '')}
                disabled={!latestActiveChannel}
              >
                <GitBranch size={12} /> Use active
              </button>
            </span>
          )}
          className="mono"
          testId="invoice-channel-id"
          value={channelId}
          onChange={setChannelId}
          validate={value => { if (value.trim()) assertHex32(value, 'Channel id'); }}
        />
        <AssetSelect value={asset} onChange={setAsset} />
        <button data-testid="invoice-create" disabled={busy || !canCreateInvoices}><Plus size={15} /> Create invoice</button>
        {!canCreateInvoices && (
          <small className="inline-error">
            {!canSign
              ? 'The current API token needs the sign scope.'
              : 'Restart Hub with MORPH_HUB_INVOICE_PRIVATE_KEY or --invoice-private-key to create signed invoices.'}
          </small>
        )}
      </form>

      <div className="form-section">
        <h3>Receive from text</h3>
        <form onSubmit={submitDecode} className="form-grid">
          <label>Encoded invoice<textarea className="mono" data-testid="invoice-decode-text" value={decodeText} onChange={event => setDecodeText(event.target.value)} /></label>
          <button data-testid="invoice-decode" disabled={busy || !canWrite}><ReceiptText size={15} /> Receive invoice</button>
        </form>
      </div>

      <div className="form-section">
        <h3>Settle</h3>
        <form onSubmit={submitSettle} className="form-grid">
          <label>Invoice
            <select data-testid="invoice-settle-id" value={settleInvoiceId} onChange={event => setSettleInvoiceId(event.target.value)}>
              <option value="">select invoice</option>
              {settleableInvoices.map(invoice => (
                <option key={invoice.invoice_id} value={invoice.invoice_id}>{shortHex(invoice.invoice_id)} · {invoice.status} · {invoice.description || formatAmount(invoice.amount, invoice.asset)}</option>
              ))}
            </select>
          </label>
          <ValidatedInput label="Payment preimage" className="mono" testId="invoice-settle-preimage" value={settlePreimage} onChange={setSettlePreimage} validate={value => { assertHex32(value, 'Payment preimage'); }} />
          <button data-testid="invoice-settle" disabled={busy || !settleInvoiceId || !canWrite}><BadgeCheck size={15} /> Settle</button>
        </form>
      </div>

      {!canWrite && <small className="inline-error">Receiving and settling invoices need the write scope.</small>}

      {latestSettleableInvoice && (
        <button className="copy-button" data-testid="invoice-copy-latest" onClick={copyLatestInvoice} disabled={busy}>
          <ReceiptText size={15} /> Copy latest invoice
        </button>
      )}
      {copyStatus && <small className={copyStatus === 'copied' ? 'inline-ok' : 'inline-error'}>{copyStatus}</small>}
    </div>
  );
}

function ActionSubTabs<T extends string>({
  items,
  active,
  onChange,
}: {
  items: { key: T; label: string; Icon: LucideIcon; disabled?: boolean }[];
  active: T;
  onChange: (key: T) => void;
}) {
  return (
    <div className="action-sub-tabs">
      {items.map(({ key, label, Icon, disabled }) => (
        <button
          key={key}
          type="button"
          className={active === key ? 'selected' : ''}
          onClick={() => onChange(key)}
          disabled={disabled}
        >
          <Icon size={14} />
          <span>{label}</span>
        </button>
      ))}
    </div>
  );
}

export function ChannelActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [activeTab, setActiveTab] = useState<ChannelActionTab>('open');
  const [spliceChannelId, setSpliceChannelId] = useState('');
  const [publishChannelId, setPublishChannelId] = useState('');
  const [finaliseChannelId, setFinaliseChannelId] = useState('');
  const [pendingFinaliseChannel, setPendingFinaliseChannel] = useState<ChannelRecord | null>(null);
  const [pendingPublication, setPendingPublication] = useState<{
    channel: ChannelRecord;
    fundingContextId: Hex32;
    stateNumber: number;
  } | null>(null);
  const [spliceEpoch, setSpliceEpoch] = useState('');
  const [spliceContextId, setSpliceContextId] = useState('');
  const [publishContextId, setPublishContextId] = useState('');
  const [publishStateNumber, setPublishStateNumber] = useState('');
  const orderedChannels = sortChannelsForOperator(state.channels, state.events);
  const activeChannels = orderedChannels.filter(channel => channel.phase === 'active');
  const publishableChannels = orderedChannels.filter(channel => channel.phase === 'active' || channel.phase === 'settling');
  const settlingChannels = orderedChannels.filter(channel => channel.phase === 'settling');
  const selectedSpliceChannel = activeChannels.find(channel => channel.channel_id === spliceChannelId);
  const selectedPublishChannel = publishableChannels.find(channel => channel.channel_id === publishChannelId);
  const selectedFinaliseChannel = settlingChannels.find(channel => channel.channel_id === finaliseChannelId);
  const canWrite = hasHubScope(state.security, 'write');

  const submitSplice = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Record splice', () => {
      const id = assertHex32(spliceChannelId, 'Channel id');
      return postAction(`/api/channels/${id}/splice`, {
        new_funding_epoch: Number(assertPositiveInteger(spliceEpoch, 'New funding epoch')),
        new_funding_context_id: assertHex32(spliceContextId, 'New funding context id'),
      });
    });
  };

  const submitPublish = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite || !selectedPublishChannel) return;
    setPendingPublication({
      channel: selectedPublishChannel,
      fundingContextId: assertHex32(publishContextId, 'Funding context id'),
      stateNumber: Number(assertPositiveInteger(publishStateNumber, 'State number')),
    });
  };

  const submitFinalise = (event: FormEvent) => {
    event.preventDefault();
    if (canWrite && selectedFinaliseChannel) setPendingFinaliseChannel(selectedFinaliseChannel);
  };

  const useSelectedSpliceDefaults = () => {
    if (!selectedSpliceChannel) return;
    setSpliceEpoch(String(selectedSpliceChannel.funding_epoch + 1));
    setSpliceContextId(randomHex32());
  };

  const useSelectedPublishDefaults = () => {
    if (!selectedPublishChannel) return;
    setPublishContextId(selectedPublishChannel.funding_context_id);
    setPublishStateNumber(String(selectedPublishChannel.state_number + 1));
  };

  return (
    <div className="drawer-section">
      <h2>Node Layer</h2>
      <p className="inline-note">Hub channel controls update local off-chain records; they do not build or broadcast CKB transactions.</p>
      {!canWrite && <small className="inline-error">The current API token needs the write scope.</small>}
      <ActionSubTabs<ChannelActionTab>
        active={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'open', label: 'Open', Icon: GitBranch, disabled: !canWrite },
          { key: 'splice', label: 'Splice', Icon: Split, disabled: !canWrite || activeChannels.length === 0 },
          { key: 'publish', label: 'Publish', Icon: RadioTower, disabled: !canWrite || publishableChannels.length === 0 },
          { key: 'finalise', label: 'Finalise', Icon: BadgeCheck, disabled: !canWrite || settlingChannels.length === 0 },
        ]}
      />
      {activeTab === 'open' && (
        <ChannelOpenForm
          mode="open"
          state={state}
          runAction={runAction}
          busy={busy}
          actionLabel="Open channel"
          submitLabel="Open channel"
          submitTestId="channel-open"
          testPrefix="channel"
          submitIcon={<GitBranch size={15} />}
          disabled={!canWrite}
          onSubmit={body => postAction('/api/channels', body)}
        />
      )}

      {activeTab === 'splice' && <div className="form-section">
        <h3>Record splice</h3>
        <form onSubmit={submitSplice} className="form-grid">
          <ChannelSelect testId="channel-splice-select" label="Active channel" channels={activeChannels} value={spliceChannelId} onChange={setSpliceChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-splice-use-selected" onClick={useSelectedSpliceDefaults} disabled={!selectedSpliceChannel}>
              <RefreshCw size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="New funding epoch" className="mono" testId="channel-splice-epoch" value={spliceEpoch} onChange={setSpliceEpoch} validate={value => { assertPositiveInteger(value, 'New funding epoch'); }} />
          <ValidatedInput label="New funding context id" className="mono" testId="channel-splice-context-id" value={spliceContextId} onChange={setSpliceContextId} validate={value => { assertHex32(value, 'New funding context id'); }} />
          <button data-testid="channel-splice" disabled={busy || !canWrite || activeChannels.length === 0}><Split size={15} /> Record splice</button>
        </form>
      </div>}

      {activeTab === 'publish' && <div className="form-section">
        <h3>Record publication · enter settling</h3>
        <form onSubmit={submitPublish} className="form-grid">
          <ChannelSelect testId="channel-publish-select" label="Trackable channel" channels={publishableChannels} value={publishChannelId} onChange={setPublishChannelId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="channel-publish-use-selected" onClick={useSelectedPublishDefaults} disabled={!selectedPublishChannel}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="Funding context id" className="mono" testId="channel-publish-context-id" value={publishContextId} onChange={setPublishContextId} validate={value => { assertHex32(value, 'Funding context id'); }} />
          <ValidatedInput label="State number" className="mono" testId="channel-publish-state-number" value={publishStateNumber} onChange={setPublishStateNumber} validate={value => { assertPositiveInteger(value, 'State number'); }} />
          <button data-testid="channel-publish" disabled={busy || !canWrite || publishableChannels.length === 0}><RadioTower size={15} /> Record publication</button>
        </form>
      </div>}

      {activeTab === 'finalise' && <div className="form-section">
        <h3>Finalise</h3>
        <form onSubmit={submitFinalise} className="form-grid">
          <ChannelSelect testId="channel-finalise-select" label="Settling channel" channels={settlingChannels} value={finaliseChannelId} onChange={setFinaliseChannelId} />
          <button data-testid="channel-finalise" disabled={busy || !canWrite || !selectedFinaliseChannel}><BadgeCheck size={15} /> Finalise channel</button>
        </form>
      </div>}
      {pendingFinaliseChannel && (
        <ConfirmActionDialog
          title={`Finalise channel ${shortHex(pendingFinaliseChannel.channel_id)}?`}
          detail={`This closes the settling channel at state ${pendingFinaliseChannel.state_number}. It cannot be undone from this console.`}
          confirmLabel="Finalise"
          busy={busy}
          onCancel={() => setPendingFinaliseChannel(null)}
          onConfirm={() => {
            const id = pendingFinaliseChannel.channel_id;
            void runAction('Finalise channel', () => postAction(`/api/channels/${id}/finalise`)).then(() => setPendingFinaliseChannel(null));
          }}
        />
      )}
      {pendingPublication && (
        <ConfirmActionDialog
          title={`Record state #${pendingPublication.stateNumber} publication?`}
          detail={`This writes a local publication record for ${shortHex(pendingPublication.channel.channel_id)} and ${pendingPublication.channel.phase === 'active' ? 'moves the channel into settling' : 'keeps the channel in settling'}. It does not broadcast a CKB transaction.`}
          confirmLabel="Enter settling"
          confirmTestId="confirm-state-publication"
          busy={busy}
          onCancel={() => setPendingPublication(null)}
          onConfirm={() => {
            const pending = pendingPublication;
            void runAction('Record state publication', () => postAction(`/api/channels/${pending.channel.channel_id}/publish`, {
              funding_context_id: pending.fundingContextId,
              state_number: pending.stateNumber,
            })).then(() => setPendingPublication(null));
          }}
        />
      )}
    </div>
  );
}

export function FactoryActions({
  state,
  runAction,
  busy,
  target,
}: {
  state: NodeState;
  runAction: RunAction;
  busy: boolean;
  target: FactoryActionTarget | null;
}) {
  const [activeTab, setActiveTab] = useState<FactoryActionTab>('open');
  const [factoryId, setFactoryId] = useState(createDraftHex32);
  const [selectedParticipantPubkeys, setSelectedParticipantPubkeys] = useState<string[]>([]);
  const [customParticipantPubkeys, setCustomParticipantPubkeys] = useState('');
  const [reserve, setReserve] = useState('');
  const [factoryAsset, setFactoryAsset] = useState<Asset>({ kind: 'ckb' });
  const [selectedFactoryId, setSelectedFactoryId] = useState('');
  const [newUpdateNumber, setNewUpdateNumber] = useState('');
  const [materialisePrefill, setMaterialisePrefill] = useState<ChannelFormPrefill | null>(null);
  const orderedFactories = sortFactoriesForOperator(state.factories, state.events);
  const selectedFactory = orderedFactories.find(factory => factory.factory_id === selectedFactoryId);
  const selectedFactoryAssets = useMemo(
    () => uniqueAssets(selectedFactory?.reserve_balances.map(balance => balance.asset) ?? []),
    [selectedFactory?.reserve_balances]
  );
  const canWrite = hasHubScope(state.security, 'write');

  useEffect(() => {
    if (!target) return;
    const targetFactory = orderedFactories.find(factory => factory.factory_id === target.factoryId);
    setSelectedFactoryId(target.factoryId);
    if (target.intent === 'advance') {
      setActiveTab('advance');
      setNewUpdateNumber(targetFactory ? String(targetFactory.update_number + 1) : '');
      return;
    }
    setActiveTab('materialise');
    setMaterialisePrefill({
      nonce: target.nonce,
      draft: {
        channelId: createDraftHex32(),
        fundingContextId: createDraftHex32(),
        pending: DEFAULT_PENDING_CAPACITY,
        sponsorBudget: DEFAULT_SPONSOR_BUDGET,
      },
    });
  }, [target?.nonce]);

  const submitOpen = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Open factory', () => {
      const customPubkeys = customParticipantPubkeys.trim()
        ? parsePubkeyList(customParticipantPubkeys, 'Custom counterparty pubkey')
        : [];
      const participant_pubkeys = uniqueStrings([
        state.pubkey,
        ...selectedParticipantPubkeys,
        ...customPubkeys,
      ]);
      assertIncludesPubkey(participant_pubkeys, state.pubkey, 'Participant pubkeys');
      if (
        participant_pubkeys.length < state.model.factory_min_participants
        || participant_pubkeys.length > state.model.factory_max_participants
      ) {
        throw new Error(
          `Current Factory profile requires ${state.model.factory_min_participants}–${state.model.factory_max_participants} unique participant pubkeys`,
        );
      }
      return postAction('/api/factories', {
        factory_id: assertHex32(factoryId, 'Factory id'),
        participant_pubkeys,
        reserve: assertPositiveInteger(reserve, 'Reserve'),
        asset: normaliseAsset(factoryAsset),
      });
    });
  };

  const submitAdvance = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Advance factory', () => {
      const id = assertHex32(selectedFactoryId, 'Factory id');
      return postAction(`/api/factories/${id}/advance`, {
        new_update_number: Number(assertPositiveInteger(newUpdateNumber, 'New update number')),
      });
    });
  };

  const toggleParticipant = (pubkey: string) => {
    setSelectedParticipantPubkeys(current => (
      current.includes(pubkey)
        ? current.filter(value => value !== pubkey)
        : [...current, pubkey]
    ));
  };

  const generateFactoryId = () => {
    setFactoryId(randomHex32());
  };

  const useSelectedFactoryUpdate = () => {
    if (!selectedFactory) return;
    setNewUpdateNumber(String(selectedFactory.update_number + 1));
  };

  return (
    <div className="drawer-section">
      <h2>Factory Layer</h2>
      <p className="inline-note">Hub Factory controls record a 2–16 participant local projection. Factory-right proofs and reserve transactions are not built here.</p>
      {!canWrite && <small className="inline-error">The current API token needs the write scope.</small>}
      <ActionSubTabs<FactoryActionTab>
        active={activeTab}
        onChange={setActiveTab}
        items={[
          { key: 'open', label: 'Open', Icon: Factory, disabled: !canWrite },
          { key: 'advance', label: 'Advance', Icon: RefreshCw, disabled: !canWrite || orderedFactories.length === 0 },
          { key: 'materialise', label: 'Child', Icon: Network, disabled: !canWrite || orderedFactories.length === 0 },
        ]}
      />
      {activeTab === 'open' && <form onSubmit={submitOpen} className="form-grid">
        <ValidatedInput
          label={(
            <span className="field-label-row">
              Factory id
              <button type="button" className="field-action" data-testid="factory-generate-id" onClick={generateFactoryId}>
                <RefreshCw size={12} /> Generate
              </button>
            </span>
          )}
          className="mono"
          testId="factory-id"
          value={factoryId}
          onChange={setFactoryId}
          validate={value => { assertHex32(value, 'Factory id'); }}
        />
        <label>
          Participants (select 1–15 counterparties)
          <div className="participant-picker" data-testid="factory-participants">
            <span className="participant-chip selected" title={state.pubkey}>
              Local {shortHex(state.pubkey)}
            </span>
            {state.peers.map(peer => {
              const selected = selectedParticipantPubkeys.includes(peer.pubkey);
              return (
                <button
                  type="button"
                  className={`participant-chip ${selected ? 'selected' : ''}`}
                  key={peer.pubkey}
                  onClick={() => toggleParticipant(peer.pubkey)}
                  title={peer.pubkey}
                >
                  {selected ? <BadgeCheck size={12} /> : <Plus size={12} />}
                  {peer.alias || shortHex(peer.pubkey)}
                </button>
              );
            })}
            {state.peers.length === 0 && <small>No connected peers yet</small>}
          </div>
        </label>
        <ValidatedTextarea
          label="Custom participant pubkeys"
          className="mono compact"
          testId="factory-participants-custom"
          value={customParticipantPubkeys}
          onChange={setCustomParticipantPubkeys}
          validate={value => {
            if (!value.trim()) return;
            const pubkeys = parsePubkeyList(value, 'Custom participant pubkey');
            if (pubkeys.length > state.model.factory_max_participants - 1) {
              throw new Error(
                `Enter at most ${state.model.factory_max_participants - 1} custom participant pubkeys`,
              );
            }
          }}
        />
        <ValidatedInput label="Reserve" className="mono" testId="factory-reserve" value={reserve} onChange={setReserve} validate={value => { assertPositiveInteger(value, 'Reserve'); }} />
        <AssetSelect value={factoryAsset} onChange={setFactoryAsset} />
        <button data-testid="factory-open" disabled={busy || !canWrite}><Factory size={15} /> Open factory</button>
      </form>}

      {activeTab === 'advance' && <div className="form-section">
        <h3>Advance</h3>
        <form onSubmit={submitAdvance} className="form-grid">
          <FactorySelect testId="factory-advance-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          <div className="field-action-row">
            <button type="button" className="field-action" data-testid="factory-advance-use-selected" onClick={useSelectedFactoryUpdate} disabled={!selectedFactory}>
              <Activity size={12} /> Use selected
            </button>
          </div>
          <ValidatedInput label="New update number" className="mono" testId="factory-new-update-number" value={newUpdateNumber} onChange={setNewUpdateNumber} validate={value => { assertPositiveInteger(value, 'New update number'); }} />
          <button data-testid="factory-advance" disabled={busy || !canWrite || orderedFactories.length === 0}><RefreshCw size={15} /> Advance</button>
        </form>
      </div>}

      {activeTab === 'materialise' && <div className="form-section">
        <h3>Materialise child</h3>
        <ChannelOpenForm
          mode="materialise"
          state={state}
          runAction={runAction}
          busy={busy}
          actionLabel="Materialise factory child"
          submitLabel="Materialise child"
          submitTestId="factory-materialise-child"
          testPrefix="factory-child"
          submitIcon={<Network size={15} />}
          prefill={materialisePrefill}
          assetOptions={selectedFactoryAssets}
          disabled={!canWrite || !selectedFactoryId || orderedFactories.length === 0}
          peers={state.peers}
          beforeFields={(
            <FactorySelect testId="factory-materialise-select" factories={orderedFactories} value={selectedFactoryId} onChange={setSelectedFactoryId} />
          )}
          onSubmit={body => {
            const id = assertHex32(selectedFactoryId, 'Factory id');
            return postAction(`/api/factories/${id}/materialise-child`, body);
          }}
        />
      </div>}
    </div>
  );
}

function ChannelOpenForm({
  mode,
  state,
  runAction,
  busy,
  actionLabel,
  submitLabel,
  submitTestId,
  testPrefix,
  submitIcon,
  onSubmit,
  beforeFields,
  disabled = false,
  prefill,
  peers = [],
  assetOptions = [],
}: {
  mode: ChannelFormMode;
  state: NodeState;
  runAction: RunAction;
  busy: boolean;
  actionLabel: string;
  submitLabel: string;
  submitTestId: string;
  testPrefix: string;
  submitIcon: React.ReactNode;
  onSubmit: (body: ReturnType<typeof channelBody>) => Promise<NodeState>;
  beforeFields?: React.ReactNode;
  disabled?: boolean;
  prefill?: ChannelFormPrefill | null;
  peers?: PeerRecord[];
  assetOptions?: Asset[];
}) {
  const [draft, setDraft] = useState<ChannelFormDraft>(() => createChannelDraft());
  const child = mode === 'materialise';
  const usePeerSelect = child && peers.length > 0;
  const idLabel = child ? 'Child channel id' : 'Channel id';
  const idTestId = child ? `${testPrefix}-channel-id` : 'channel-id';

  useEffect(() => {
    if (!prefill) return;
    setDraft(current => ({ ...current, ...prefill.draft }));
  }, [prefill?.nonce]);

  useEffect(() => {
    if (!usePeerSelect) return;
    setDraft(current => (
      current.counterpartyPubkey
        ? current
        : { ...current, counterpartyPubkey: peers[0].pubkey, counterpartyAlias: '' }
    ));
  }, [usePeerSelect, peers]);

  useEffect(() => {
    if (!child || assetOptions.length === 0) return;
    setDraft(current => {
      const selectedKey = assetKey(current.asset);
      const selected = assetOptions.find(asset => assetKey(asset) === selectedKey);
      return selected ? current : { ...current, asset: assetOptions[0] };
    });
  }, [child, assetOptions]);

  const updateDraft = <Key extends keyof ChannelFormDraft>(key: Key, value: ChannelFormDraft[Key]) => {
    setDraft(current => ({ ...current, [key]: value }));
  };

  const generateIds = () => {
    setDraft(current => ({
      ...current,
      channelId: randomHex32(),
      fundingContextId: randomHex32(),
    }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (disabled) return;
    void runAction(actionLabel, () => onSubmit(channelBody({
      channelId: draft.channelId,
      counterpartyPubkey: draft.counterpartyPubkey,
      counterpartyAlias: draft.counterpartyAlias,
      fundingContextId: draft.fundingContextId,
      local: draft.local,
      remote: draft.remote,
      pending: draft.pending,
      sponsorBudget: draft.sponsorBudget,
      asset: draft.asset,
      localPubkey: state.pubkey,
      child,
    })));
  };

  return (
    <form onSubmit={submit} className="form-grid">
      {beforeFields}
      <div className="field-action-row">
        <button type="button" className="field-action" data-testid={child ? 'factory-child-generate-ids' : 'channel-generate-ids'} onClick={generateIds}>
          <RefreshCw size={12} /> Generate ids
        </button>
      </div>
      <ValidatedInput label={idLabel} className="mono" testId={idTestId} value={draft.channelId} onChange={value => updateDraft('channelId', value)} validate={value => { assertHex32(value, idLabel); }} />
      {usePeerSelect ? (
        <label>Counterparty
          <select data-testid={`${testPrefix}-counterparty-pubkey`} value={draft.counterpartyPubkey} onChange={event => updateDraft('counterpartyPubkey', event.target.value)}>
            {peers.map(peer => (
              <option key={peer.pubkey} value={peer.pubkey}>{peer.alias || shortHex(peer.pubkey)} · {shortHex(peer.pubkey)}</option>
            ))}
          </select>
        </label>
      ) : (
        <>
          <ValidatedInput label="Counterparty pubkey" className="mono" testId={`${testPrefix}-counterparty-pubkey`} value={draft.counterpartyPubkey} onChange={value => updateDraft('counterpartyPubkey', value)} validate={value => { assertRemotePubkey(value, state.pubkey, 'Counterparty pubkey'); }} />
          <ValidatedInput label="Counterparty alias" testId={`${testPrefix}-counterparty-alias`} value={draft.counterpartyAlias} maxLength={MAX_PEER_ALIAS_LEN} onChange={value => updateDraft('counterpartyAlias', value)} validate={() => {}} />
        </>
      )}
      <ValidatedInput label="Funding context id" className="mono" testId={`${testPrefix}-funding-context-id`} value={draft.fundingContextId} onChange={value => updateDraft('fundingContextId', value)} validate={value => { assertHex32(value, 'Funding context id'); }} />
      <ValidatedInput label="Local capacity" className="mono" testId={`${testPrefix}-local`} value={draft.local} onChange={value => updateDraft('local', value)} validate={value => { assertPositiveInteger(value, 'Local capacity'); }} />
      <ValidatedInput label="Remote capacity" className="mono" testId={`${testPrefix}-remote`} value={draft.remote} onChange={value => updateDraft('remote', value)} validate={value => { assertPositiveInteger(value, 'Remote capacity'); }} />
      <ValidatedInput label="Pending capacity" className="mono" testId={`${testPrefix}-pending`} value={draft.pending} onChange={value => updateDraft('pending', value)} validate={value => { assertNonNegativeInteger(value, 'Pending capacity'); }} />
      <ValidatedInput label="Sponsor budget" className="mono" testId={`${testPrefix}-sponsor-budget`} value={draft.sponsorBudget} onChange={value => updateDraft('sponsorBudget', value)} validate={value => { assertPositiveInteger(value, 'Sponsor budget'); }} />
      {child && assetOptions.length > 0 ? (
        <label>Reserve asset
          <select
            data-testid={`${testPrefix}-asset`}
            value={assetKey(draft.asset)}
            onChange={event => {
              const asset = assetOptions.find(option => assetKey(option) === event.target.value);
              if (asset) updateDraft('asset', asset);
            }}
          >
            {assetOptions.map(asset => <option key={assetKey(asset)} value={assetKey(asset)}>{assetLabel(asset)}</option>)}
          </select>
        </label>
      ) : (
        <AssetSelect value={draft.asset} onChange={asset => updateDraft('asset', asset)} />
      )}
      <button data-testid={submitTestId} disabled={busy || disabled}>{submitIcon}{submitLabel}</button>
    </form>
  );
}

export function StateActions({ state, runAction, busy }: { state: NodeState; runAction: RunAction; busy: boolean }) {
  const [raw, setRaw] = useState('');
  const [stateFileStatus, setStateFileStatus] = useState('');
  const [stateFileBusy, setStateFileBusy] = useState(false);
  const [restoreAcknowledged, setRestoreAcknowledged] = useState(false);
  const [restoreCandidate, setRestoreCandidate] = useState<{ payload: unknown; preview: RestorePreview } | null>(null);
  const canRestore = hasHubScope(state.security, 'restore');
  const restoreAvailable = state.security.state_restore_enabled && canRestore;
  const [recoveryJson, setRecoveryJson] = useState('');
  const [recoveryStatus, setRecoveryStatus] = useState('');
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const canWrite = hasHubScope(state.security, 'write');

  const loadRecovery = async (id: string) => {
    setRecoveryBusy(true);
    setRecoveryStatus('');
    try { setRecoveryJson(JSON.stringify(await getMultiAssetRecoveryPackage(id), null, 2)); }
    catch (error) { setRecoveryStatus((error as Error).message); }
    finally { setRecoveryBusy(false); }
  };

  const importRecovery = (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    void runAction('Retain multi-asset recovery', () => {
      if (recoveryJson.length > 128 * 1024) throw new Error('Recovery JSON exceeds 128 KiB');
      const packageValue: unknown = JSON.parse(requiredText(recoveryJson, 'Recovery package JSON'));
      return postAction('/api/multi-asset-packages', packageValue);
    });
  };

  const exportState = async () => {
    if (!canRestore) return;
    setStateFileBusy(true);
    setStateFileStatus('');
    try {
      const file = await getStateFile();
      setRaw(JSON.stringify(file, null, 2));
      setStateFileStatus('loaded');
    } catch (err) {
      setStateFileStatus(String((err as Error).message));
    } finally {
      setStateFileBusy(false);
    }
  };

  const requestRestore = async () => {
    if (!restoreAvailable) return;
    setStateFileStatus('');
    setRestoreCandidate(null);
    setStateFileBusy(true);
    try {
      const payload = JSON.parse(requiredText(raw, 'State file JSON'));
      const preview = await previewStateFile(payload);
      if (!preview.allowed) {
        setStateFileStatus(`Restore blocked: ${preview.warnings.join('; ')}`);
        return;
      }
      setRestoreCandidate({ payload, preview });
    } catch (err) {
      setStateFileStatus(String((err as Error).message));
    } finally {
      setStateFileBusy(false);
    }
  };

  const restoreState = () => {
    const candidate = restoreCandidate;
    if (candidate == null) return;
    void runAction('Restore state file', () => replaceStateFile(candidate.payload, candidate.preview.confirmation_hash)).then(() => {
      setRestoreCandidate(null);
      setRestoreAcknowledged(false);
    });
  };

  return (
    <div className="drawer-section">
      <h2>Multi-asset recovery</h2>
      <p>Retain signed withdrawal evidence for the current channel state.</p>
      <form className="form-grid" onSubmit={importRecovery}>
        <label>Recovery package JSON
          <textarea className="mono" data-testid="multi-asset-recovery-json" maxLength={128 * 1024} value={recoveryJson} onChange={event => setRecoveryJson(event.target.value)} />
        </label>
        <button data-testid="multi-asset-recovery-import" disabled={busy || recoveryBusy || !canWrite || !recoveryJson.trim()}><Upload size={15} /> Validate and retain</button>
      </form>
      {recoveryStatus && <small className="inline-error">{recoveryStatus}</small>}
      <div className="stack-list">
        {state.multi_asset_packages.map(packageValue => (
          <button type="button" className="copy-button" key={packageValue.package_id} disabled={busy || recoveryBusy} onClick={() => { void loadRecovery(packageValue.package_id); }}>
            <FileJson size={15} /> {shortHex(packageValue.channel_id)} · state {packageValue.state_number} · {packageValue.vault_count} assets
          </button>
        ))}
      </div>
      <h2>State File</h2>
      <div className="state-path">
        <strong>{state.state_path || 'not loaded'}</strong>
        <small>{state.security.state_restore_enabled ? 'Empty bootstrap restore is enabled for this API process' : 'Restore is disabled by default'}</small>
      </div>
      <button className="copy-button" data-testid="state-load-json" onClick={exportState} disabled={busy || stateFileBusy || !canRestore}><FileJson size={15} /> Load state JSON</button>
      {stateFileStatus && <small className={stateFileStatus === 'loaded' ? 'inline-ok' : 'inline-error'}>{stateFileStatus}</small>}
      <textarea className="mono" data-testid="state-json" value={raw} onChange={event => setRaw(event.target.value)} />
      <label className="check-row">
        <input
          type="checkbox"
          checked={restoreAcknowledged}
          onChange={event => setRestoreAcknowledged(event.target.checked)}
          disabled={!restoreAvailable}
        />
        <span>I understand this only restores an empty bootstrap state. Operational records are rejected until chain-anchored restore is implemented.</span>
      </label>
      <button
        className="danger-button"
        data-testid="state-restore-json"
        onClick={() => { void requestRestore(); }}
        disabled={busy || stateFileBusy || !raw.trim() || !restoreAvailable || !restoreAcknowledged}
      >
        <Upload size={15} /> Restore state file
      </button>
      {!canRestore && <small className="inline-error">The current API token needs the restore scope.</small>}
      {canRestore && !state.security.state_restore_enabled && (
        <small className="inline-error">Restart with --allow-state-restore to enable this write path.</small>
      )}
      {restoreCandidate != null && (
        <ConfirmActionDialog
          title="Restore local Hub state file?"
          detail={`This replaces ${state.state_path || 'the current Hub state file'} with the JSON in the editor. The API writes a private backup before commit. Confirmation hash ${restoreCandidate.preview.confirmation_hash}. Current ${formatRestoreSummary(restoreCandidate.preview.current)}. Candidate ${formatRestoreSummary(restoreCandidate.preview.candidate)}.`}
          confirmLabel="Restore"
          confirmTestId="confirm-state-restore"
          busy={busy}
          onCancel={() => setRestoreCandidate(null)}
          onConfirm={restoreState}
        />
      )}
    </div>
  );
}

function formatRestoreSummary(summary: RestorePreview['current']): string {
  return `${summary.peers} peers, ${summary.channels} channels, ${summary.factories} factories, ${summary.invoices} invoices, ${summary.completed_flows} flows, ${summary.events} events`;
}

function ChannelSelect({
  channels,
  value,
  onChange,
  label = 'Channel id',
  testId,
}: {
  channels: ChannelRecord[];
  value: string;
  onChange: (value: string) => void;
  label?: string;
  testId: string;
}) {
  return (
    <label>{label}
      <select data-testid={testId} value={value} onChange={event => onChange(event.target.value)}>
        <option value="">select channel</option>
        {channels.map(channel => (
          <option key={channel.channel_id} value={channel.channel_id}>{shortHex(channel.channel_id)} · {channel.phase}</option>
        ))}
      </select>
    </label>
  );
}

function FactorySelect({ factories, value, onChange, testId }: { factories: FactoryRecord[]; value: string; onChange: (value: string) => void; testId: string }) {
  return (
    <label>Factory id
      <select data-testid={testId} value={value} onChange={event => onChange(event.target.value)}>
        <option value="">select factory</option>
        {factories.map(factory => (
          <option key={factory.factory_id} value={factory.factory_id}>{shortHex(factory.factory_id)} · update {factory.update_number}</option>
        ))}
      </select>
    </label>
  );
}

function channelBody(input: {
  channelId: string;
  counterpartyPubkey: string;
  counterpartyAlias: string;
  fundingContextId: string;
  local: string;
  remote: string;
  pending: string;
  sponsorBudget: string;
  asset: Asset;
  localPubkey: Pubkey;
  child?: boolean;
}) {
  const base = {
    counterparty_pubkey: assertRemotePubkey(input.counterpartyPubkey, input.localPubkey, 'Counterparty pubkey'),
    counterparty_alias: input.counterpartyAlias.trim() || undefined,
    funding_context_id: assertHex32(input.fundingContextId, 'Funding context id'),
    local: assertPositiveInteger(input.local, 'Local capacity'),
    remote: assertPositiveInteger(input.remote, 'Remote capacity'),
    pending: input.pending.trim() ? assertNonNegativeInteger(input.pending, 'Pending capacity') : undefined,
    sponsor_budget: Number(assertPositiveInteger(input.sponsorBudget, 'Sponsor budget')),
    asset: normaliseAsset(input.asset),
  };
  if (input.child) {
    return { ...base, child_channel_id: assertHex32(input.channelId, 'Child channel id') };
  }
  return { ...base, channel_id: assertHex32(input.channelId, 'Channel id') };
}

function createChannelDraft(overrides: Partial<ChannelFormDraft> = {}): ChannelFormDraft {
  return {
    channelId: createDraftHex32(),
    counterpartyPubkey: '',
    counterpartyAlias: '',
    fundingContextId: createDraftHex32(),
    local: '',
    remote: '',
    pending: DEFAULT_PENDING_CAPACITY,
    sponsorBudget: DEFAULT_SPONSOR_BUDGET,
    asset: { kind: 'ckb' },
    ...overrides,
  };
}

function assetKey(asset: Asset): string {
  return asset.kind === 'ckb' ? 'ckb' : `xudt:${asset.type_hash ?? 'unknown'}`;
}

function uniqueAssets(assets: Asset[]): Asset[] {
  const seen = new Set<string>();
  return assets.filter(asset => {
    const key = assetKey(asset);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function createDraftHex32(): string {
  try {
    return randomHex32();
  } catch {
    return '';
  }
}
