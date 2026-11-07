import { Boxes, Factory, GitBranch, Network, ReceiptText, ShieldCheck } from 'lucide-react';
import type { HubModel } from './domain';

type ModelBoundaryPanelProps = {
  model: HubModel;
};

export function ModelBoundaryPanel({ model }: ModelBoundaryPanelProps) {
  const surfaces = [
    {
      key: 'factory-rights',
      label: 'Factory rights',
      detail: model.factory_rights_exposed ? 'Proof and reservation evidence available' : 'Rights and reservations are not exposed by Hub',
      exposed: model.factory_rights_exposed,
      Icon: Factory,
    },
    {
      key: 'provider-edges',
      label: 'Provider edges',
      detail: model.provider_edges_exposed ? 'Edge lifecycle evidence available' : 'Reserved-to-disabled edge lifecycle is not exposed',
      exposed: model.provider_edges_exposed,
      Icon: Network,
    },
    {
      key: 'rgbpp-evidence',
      label: 'RGB++ evidence',
      detail: model.rgbpp_evidence_exposed ? 'Proof commitment and freshness available' : 'Identity, SPV and reorg evidence are not exposed',
      exposed: model.rgbpp_evidence_exposed,
      Icon: Boxes,
    },
    {
      key: 'payment-gateway-receipts',
      label: 'Payment Gateway receipts',
      detail: model.payment_gateway_receipts_exposed ? 'Terminal receipt evidence available' : 'Payment Gateway handles application payments and access',
      exposed: model.payment_gateway_receipts_exposed,
      Icon: ReceiptText,
    },
  ];

  return (
    <section className="panel model-boundary-panel" data-testid="model-boundary-panel">
      <div className="section-head model-boundary-head">
        <div>
          <span className="eyebrow">Sovereign model boundary</span>
          <h2>Authority path</h2>
        </div>
        <span className="badge remaining">local projection</span>
      </div>

      <div className="authority-path" aria-label="Factory right to materialised channel to provider edge">
        <article>
          <Factory size={17} />
          <span>Factory State + Vault</span>
          <strong>protocol authority</strong>
        </article>
        <span className="authority-arrow" aria-hidden="true">→</span>
        <article>
          <GitBranch size={17} />
          <span>Materialised channel</span>
          <strong>State + Vault authority</strong>
        </article>
        <span className="authority-arrow" aria-hidden="true">→</span>
        <article>
          <Network size={17} />
          <span>Provider edge</span>
          <strong>optional routing export</strong>
        </article>
      </div>

      <div className="model-boundary-note">
        <ShieldCheck size={16} />
        <div>
          <strong>Hub records are not settlement evidence</strong>
          <span>
            Profile {model.profile}; Factory signer sets support {model.factory_min_participants}–{model.factory_max_participants} participants.
            This console records local operator intent and does not build or broadcast chain transactions.
          </span>
        </div>
      </div>

      <div className="model-surface-grid">
        {surfaces.map(({ key, label, detail, exposed, Icon }) => (
          <article className={exposed ? 'exposed' : 'not-exposed'} key={key}>
            <Icon size={15} />
            <div>
              <strong>{label}</strong>
              <span>{detail}</span>
            </div>
            <small>{exposed ? 'available' : 'not in Hub'}</small>
          </article>
        ))}
      </div>
    </section>
  );
}
