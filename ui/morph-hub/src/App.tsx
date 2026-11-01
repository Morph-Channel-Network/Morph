import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Bell,
  Boxes,
  Database,
  Factory,
  FileJson,
  GitBranch,
  Landmark,
  LayoutDashboard,
  Network,
  PanelRightClose,
  PanelRightOpen,
  RadioTower,
  ReceiptText,
  RefreshCw,
  Search,
  ShieldCheck,
  Split,
  Users,
  WalletCards,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type React from 'react';
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import packageMetadata from '../package.json';
import { getState, hasApiToken, openEventStream, setApiToken } from './api';
import { useModalFocus } from './components';
import {
  Asset,
  Balance,
  FlowKey,
  Hex32,
  NodeState,
  RecordProvenance,
  emptyState,
  formatAmount,
  hasHubScope,
  shortHex,
} from './domain';
import { ChannelTable, EventPanel, FactoryPanel, InvoicePanel, PeerPanel, WatchtowerPanel } from './records';
import { ChannelActions, FactoryActions, InvoiceActions, PeerActions, StateActions } from './actions';
import { ModelBoundaryPanel } from './model';
import {
  balanceTotal,
  channelSearchText,
  eventSearchText,
  factorySearchText,
  filterRecords,
  formatActionError,
  invoiceSearchText,
  isAuthTokenError,
  latestEventId,
  lastRefreshLabel,
  liveLabel,
  liveTone,
  peerSearchText,
  queryTokens,
  rpcDetail,
  rpcLabel,
  rpcTone,
  sortChannelsForOperator,
  sortEventsNewestFirst,
  sortFactoriesForOperator,
  sortPeersForOperator,
  sortWatchtowerAlertsNewestFirst,
  watchtowerAlertSearchText,
} from './state';

type ActionPanel = 'peer' | 'invoice' | 'channel' | 'factory' | 'state';
type ToastTone = 'info' | 'ok' | 'bad';
type Toast = {
  id: number;
  tone: ToastTone;
  title: string;
  body?: string;
};
type RecordBreakdown = {
  channels: number;
  invoices: number;
  peers: number;
  factories: number;
  alerts: number;
  events: number;
};
type RunAction = (label: string, action: () => Promise<NodeState>) => Promise<void>;
type LiveMode = 'starting' | 'sse' | 'sse-reconnecting' | 'polling' | 'polling-auth' | 'offline';
type FactoryActionTarget = {
  factoryId: Hex32;
  intent: 'advance' | 'materialise';
  nonce: number;
};
const LIVE_POLL_INTERVAL_MS = 5_000;
const DRAWER_COLLAPSED_STORAGE_KEY = 'morph-hub.drawer-collapsed';
const ACTIVE_ACTION_STORAGE_KEY = 'morph-hub.active-action';

function formatAssetPortfolio(balances: Balance[]): string {
  const totals = new Map<string, { asset: Asset; amount: bigint }>();
  for (const balance of balances) {
    const key = balance.asset.kind === 'ckb' ? 'ckb' : `xudt:${balance.asset.type_hash ?? 'unknown'}`;
    const current = totals.get(key);
    totals.set(key, {
      asset: balance.asset,
      amount: (current?.amount ?? 0n) + balanceTotal(balance),
    });
  }
  if (totals.size === 0) return 'No local records';
  return [...totals.values()]
    .sort((left, right) => (left.asset.kind === 'ckb' ? -1 : 1) - (right.asset.kind === 'ckb' ? -1 : 1))
    .map(({ asset, amount }) => (
      asset.kind === 'ckb'
        ? formatAmount(amount, asset)
        : `${formatAmount(amount, asset)} · ${shortHex(asset.type_hash)}`
    ))
    .join(' / ');
}

const actionItems: { key: ActionPanel; label: string; Icon: LucideIcon }[] = [
  { key: 'peer', label: 'Peers', Icon: Users },
  { key: 'invoice', label: 'Invoices', Icon: ReceiptText },
  { key: 'channel', label: 'Channels', Icon: GitBranch },
  { key: 'factory', label: 'Factories', Icon: Factory },
  { key: 'state', label: 'State file', Icon: FileJson },
];

const flowItems: Record<FlowKey, { label: string; detail: string; action: string; panel: ActionPanel; Icon: LucideIcon }> = {
  peer: { label: 'Connect a peer', detail: 'Counterparty is known by the node', action: 'Open peers', panel: 'peer', Icon: Users },
  'invoice-created': { label: 'Create an invoice', detail: 'Payment request exists in Hub state', action: 'Open invoices', panel: 'invoice', Icon: ReceiptText },
  'invoice-received': { label: 'Receive an invoice', detail: 'Incoming invoice is decoded and stored', action: 'Open invoices', panel: 'invoice', Icon: ReceiptText },
  'invoice-settled': { label: 'Settle an invoice', detail: 'Payment preimage has closed the invoice', action: 'Open invoices', panel: 'invoice', Icon: BadgeCheck },
  'channel-opened': { label: 'Open a channel', detail: 'Active bilateral channel is tracked', action: 'Open channels', panel: 'channel', Icon: GitBranch },
  'state-published': { label: 'Record state publication', detail: 'Local channel projection entered settlement', action: 'Open channels', panel: 'channel', Icon: RadioTower },
  'channel-finalised': { label: 'Finalise a channel', detail: 'Settling channel is closed', action: 'Open channels', panel: 'channel', Icon: BadgeCheck },
  'channel-spliced': { label: 'Record a splice', detail: 'Funding context advanced locally', action: 'Open channels', panel: 'channel', Icon: Split },
  'factory-opened': { label: 'Open a factory', detail: 'Shared factory reserve is tracked', action: 'Open factories', panel: 'factory', Icon: Factory },
  'factory-advanced': { label: 'Advance a factory', detail: 'Factory update number moved forward', action: 'Open factories', panel: 'factory', Icon: RefreshCw },
  'factory-child': { label: 'Record materialised child', detail: 'Local Factory record links a child channel', action: 'Open factories', panel: 'factory', Icon: Network },
};

const sectionIds = {
  overview: 'section-overview',
  channels: 'section-channels',
  invoices: 'section-invoices',
  peers: 'section-peers',
  factories: 'section-factories',
  watchtower: 'section-watchtower',
  events: 'section-events',
} as const;

type SectionKey = keyof typeof sectionIds;

export function App() {
  const [state, setState] = useState<NodeState>(emptyState);
  const [activeAction, setActiveAction] = useState<ActionPanel>(initialActionPanel);
  const [drawerCollapsed, setDrawerCollapsed] = useState(() => initialDrawerCollapsed());
  const [status, setStatus] = useState('Loading Morph Hub API');
  const [lastRefreshMs, setLastRefreshMs] = useState<number | null>(null);
  const [clockMs, setClockMs] = useState(Date.now());
  const [error, setError] = useState('');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [busy, setBusy] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [liveMode, setLiveMode] = useState<LiveMode>('starting');
  const [authTokenPresent, setAuthTokenPresent] = useState(hasApiToken());
  const [requiresToken, setRequiresToken] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');
  const [initialStateLoaded, setInitialStateLoaded] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionKey>(initialSection);
  const [recordQuery, setRecordQuery] = useState('');
  const [factoryActionTarget, setFactoryActionTarget] = useState<FactoryActionTarget | null>(null);
  const workspaceRef = useRef<HTMLElement | null>(null);
  const latestEventIdRef = useRef(0);
  const toastIdRef = useRef(0);

  const dismissToast = useCallback((id: number) => {
    setToasts(current => current.filter(toast => toast.id !== id));
  }, []);

  const pushToast = useCallback((toast: Omit<Toast, 'id'>, ttlMs = 5_000) => {
    const id = toastIdRef.current + 1;
    toastIdRef.current = id;
    setToasts(current => [...current.filter(item => item.id !== id), { ...toast, id }].slice(-3));
    window.setTimeout(() => dismissToast(id), ttlMs);
    return id;
  }, [dismissToast]);

  const replaceToast = useCallback((id: number, toast: Omit<Toast, 'id'>, ttlMs = 5_000) => {
    setToasts(current => current.map(item => item.id === id ? { ...toast, id } : item));
    window.setTimeout(() => dismissToast(id), ttlMs);
  }, [dismissToast]);

  const applyState = useCallback((next: NodeState) => {
    latestEventIdRef.current = latestEventId(next.events);
    setState(next);
    setLastRefreshMs(Date.now());
  }, []);

  const refresh = useCallback(async () => {
    const next = await getState();
    applyState(next);
    setError('');
    setRequiresToken(false);
    setInitialStateLoaded(true);
    setStatus('State refreshed from Morph Hub API');
    return next;
  }, [applyState]);

  useEffect(() => {
    refresh().catch(err => {
      const message = String((err as Error).message);
      setRequiresToken(isAuthTokenError(message));
      setInitialStateLoaded(false);
      setError(message);
      setStatus('Morph Hub API is not reachable');
      setLiveMode('offline');
    });
  }, [refresh]);

  useEffect(() => {
    const interval = window.setInterval(() => setClockMs(Date.now()), 1_000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    const section = initialSection();
    const frame = window.requestAnimationFrame(() => {
      workspaceRef.current
        ?.querySelector<HTMLElement>(`#${sectionIds[section]}`)
        ?.scrollIntoView({ block: 'start' });
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.tagName === 'SELECT';
      if (document.querySelector('[role="dialog"]')) return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen(true);
        return;
      }
      if (!typing && event.key === '/') {
        event.preventDefault();
        const search = document.querySelector<HTMLInputElement>('[data-testid="operator-search"]');
        search?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    let stopped = false;
    if (!initialStateLoaded) {
      return () => {
        stopped = true;
      };
    }
    const refreshFromLive = async (message: string) => {
      const previousEventId = latestEventIdRef.current;
      try {
        const next = await getState();
        if (stopped) return;
        const nextEventId = latestEventId(next.events);
        applyState(next);
        setError('');
        if (nextEventId !== previousEventId) {
          setStatus(message);
        }
      } catch (err) {
        if (stopped) return;
        const message = String((err as Error).message);
        setLiveMode('offline');
        setRequiresToken(isAuthTokenError(message));
        setInitialStateLoaded(false);
        setError(message);
      }
    };

    const eventSource = openEventStream();
    if (eventSource) {
      setLiveMode('sse-reconnecting');
      const onHubEvent = () => {
        void refreshFromLive('Live event received from Morph Hub');
      };
      eventSource.onopen = () => {
        if (!stopped) setLiveMode('sse');
      };
      eventSource.onerror = () => {
        if (!stopped) setLiveMode('sse-reconnecting');
      };
      eventSource.addEventListener('morph-hub-event', onHubEvent);
      return () => {
        stopped = true;
        eventSource.removeEventListener('morph-hub-event', onHubEvent);
        eventSource.close();
      };
    }

    setLiveMode(authTokenPresent ? 'polling-auth' : 'polling');
    const interval = window.setInterval(() => {
      if (document.visibilityState !== 'hidden') {
        void refreshFromLive('State changed during live polling');
      }
    }, LIVE_POLL_INTERVAL_MS);
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [applyState, authTokenPresent, initialStateLoaded]);

  // Track which section is in view for sidebar highlighting.
  useEffect(() => {
    const root = workspaceRef.current;
    if (!root) return;
    const sections: SectionKey[] = ['overview', 'channels', 'invoices', 'peers', 'factories', 'watchtower', 'events'];
    const observer = new IntersectionObserver(
      entries => {
        const visible = entries
          .filter(entry => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]) {
          const id = (visible[0].target as HTMLElement).id;
          const match = (Object.keys(sectionIds) as SectionKey[]).find(key => sectionIds[key] === id);
          if (match) {
            setActiveSection(match);
            const nextHash = `#${sectionIds[match]}`;
            if (window.location.hash !== nextHash) window.history.replaceState(null, '', nextHash);
          }
        }
      },
      { root, rootMargin: '-20% 0px -60% 0px', threshold: [0, 0.25, 0.5, 1] }
    );
    sections.forEach(key => {
      const el = root.querySelector(`#${sectionIds[key]}`);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [state]);

  const runAction: RunAction = async (label, action) => {
    setBusy(true);
    setError('');
    setStatus(`${label} submitted`);
    const toastId = pushToast({ tone: 'info', title: `${label} submitted` });
    try {
      const next = await action();
      applyState(next);
      setStatus(`${label} accepted by Morph Hub API`);
      replaceToast(toastId, { tone: 'ok', title: `${label} accepted`, body: 'Morph Hub state refreshed.' });
    } catch (err) {
      const message = formatActionError(label, err);
      setStatus(`${label} rejected`);
      replaceToast(toastId, { tone: 'bad', title: `${label} rejected`, body: message }, 8_000);
    } finally {
      setBusy(false);
    }
  };

  const totals = useMemo(() => {
    const sponsorBudget = state.channels.reduce((sum, channel) => sum + BigInt(channel.sponsor_budget), 0n);
    const settlingStates = state.channels.filter(channel => channel.phase === 'settling').length;
    const channelValue = formatAssetPortfolio(state.channels.flatMap(channel => channel.balances));
    const factoryReserve = formatAssetPortfolio(state.factories.flatMap(factory => factory.reserve_balances));
    return { channelValue, sponsorBudget, settlingStates, factoryReserve };
  }, [state.channels, state.factories]);
  const evidence = useMemo(() => evidenceSummary(state), [state]);
  const canWrite = hasHubScope(state.security, 'write');

  const flowDataLoaded = state.required_flows.length > 0;
  const completedCount = state.completed_flows.length;
  const requiredCount = flowDataLoaded ? state.required_flows.length : 1;
  const flowCoverage = flowDataLoaded ? Math.round((completedCount / requiredCount) * 100) : 0;
  const authRequired = requiresToken || state.security.auth_required;
  const activeActionLabel = actionItems.find(item => item.key === activeAction)?.label ?? 'Actions';
  const orderedEvents = useMemo(() => sortEventsNewestFirst(state.events), [state.events]);
  const orderedChannels = useMemo(() => sortChannelsForOperator(state.channels, state.events), [state.channels, state.events]);
  const orderedPeers = useMemo(() => sortPeersForOperator(state.peers, state.events), [state.peers, state.events]);
  const orderedFactories = useMemo(() => sortFactoriesForOperator(state.factories, state.events), [state.factories, state.events]);
  const orderedWatchtowerAlerts = useMemo(() => sortWatchtowerAlertsNewestFirst(state.watchtower.alerts), [state.watchtower.alerts]);
  const recordSearchTokens = useMemo(() => queryTokens(recordQuery), [recordQuery]);
  const searchActive = recordSearchTokens.length > 0;
  const filteredChannels = useMemo(
    () => filterRecords(orderedChannels, recordSearchTokens, channelSearchText),
    [orderedChannels, recordSearchTokens]
  );
  const filteredInvoices = useMemo(
    () => filterRecords(state.invoices, recordSearchTokens, invoiceSearchText),
    [state.invoices, recordSearchTokens]
  );
  const filteredPeers = useMemo(
    () => filterRecords(orderedPeers, recordSearchTokens, peerSearchText),
    [orderedPeers, recordSearchTokens]
  );
  const filteredFactories = useMemo(
    () => filterRecords(orderedFactories, recordSearchTokens, factorySearchText),
    [orderedFactories, recordSearchTokens]
  );
  const filteredWatchtowerAlerts = useMemo(
    () => filterRecords(orderedWatchtowerAlerts, recordSearchTokens, watchtowerAlertSearchText),
    [orderedWatchtowerAlerts, recordSearchTokens]
  );
  const filteredEvents = useMemo(
    () => filterRecords(orderedEvents, recordSearchTokens, eventSearchText),
    [orderedEvents, recordSearchTokens]
  );
  const totalRecordCount =
    state.channels.length +
    state.invoices.length +
    state.peers.length +
    state.factories.length +
    orderedWatchtowerAlerts.length +
    state.events.length;
  const matchedRecordCount =
    filteredChannels.length +
    filteredInvoices.length +
    filteredPeers.length +
    filteredFactories.length +
    filteredWatchtowerAlerts.length +
    filteredEvents.length;
  const recordBreakdown: RecordBreakdown = searchActive
    ? {
      channels: filteredChannels.length,
      invoices: filteredInvoices.length,
      peers: filteredPeers.length,
      factories: filteredFactories.length,
      alerts: filteredWatchtowerAlerts.length,
      events: filteredEvents.length,
    }
    : {
      channels: state.channels.length,
      invoices: state.invoices.length,
      peers: state.peers.length,
      factories: state.factories.length,
      alerts: orderedWatchtowerAlerts.length,
      events: state.events.length,
    };

  const scrollTo = (key: SectionKey) => {
    const root = workspaceRef.current;
    const el = root?.querySelector(`#${sectionIds[key]}`) as HTMLElement | null;
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActiveSection(key);
    window.history.replaceState(null, '', `#${sectionIds[key]}`);
  };

  const selectAction = (key: ActionPanel) => {
    setActiveAction(key);
    sessionStorage.setItem(ACTIVE_ACTION_STORAGE_KEY, key);
    setDrawerCollapsed(false);
    setError('');
    const label = actionItems.find(item => item.key === key)?.label ?? 'Operator';
    setStatus(`${label} controls selected`);
  };

  const openFactoryMaterialise = (factoryId: Hex32) => {
    setFactoryActionTarget({ factoryId, intent: 'materialise', nonce: Date.now() });
    setActiveAction('factory');
    sessionStorage.setItem(ACTIVE_ACTION_STORAGE_KEY, 'factory');
    setError('');
    setStatus(`Materialise child controls selected for ${shortHex(factoryId)}`);
  };

  const toggleDrawerCollapsed = () => {
    setDrawerCollapsed(current => {
      const next = !current;
      sessionStorage.setItem(DRAWER_COLLAPSED_STORAGE_KEY, String(next));
      return next;
    });
  };

  const submitApiToken = (event: FormEvent) => {
    event.preventDefault();
    setApiToken(tokenDraft);
    setAuthTokenPresent(hasApiToken());
    setRequiresToken(false);
    setError('');
    setStatus('API token stored for this browser session');
    refresh().catch(err => {
      const message = String((err as Error).message);
      setRequiresToken(isAuthTokenError(message));
      setInitialStateLoaded(false);
      setError(message);
      setStatus('API token rejected');
      setLiveMode('offline');
    });
  };

  return (
    <main className={`app-shell ${drawerCollapsed ? 'drawer-collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">M</div>
          <div>
            <strong>Morph Hub</strong>
            <span>Operator console · v{packageMetadata.version}</span>
          </div>
        </div>

        <nav className="nav">
          <span className="nav-label">Monitor</span>
          <button className="nav-item" data-testid="command-palette-open" onClick={() => setCommandOpen(true)}>
            <Search size={16} />
            <span className="label">Command</span>
            <span className="count">⌘K</span>
          </button>
          <NavButton
            Icon={LayoutDashboard}
            label="Overview"
            testId="nav-overview"
            active={activeSection === 'overview'}
            onClick={() => scrollTo('overview')}
          />
          <NavButton
            Icon={GitBranch}
            label="Channels"
            testId="nav-channels"
            count={state.channels.length}
            active={activeSection === 'channels'}
            onClick={() => scrollTo('channels')}
          />
          <NavButton
            Icon={ReceiptText}
            label="Invoices"
            testId="nav-invoices"
            count={state.invoices.length}
            active={activeSection === 'invoices'}
            onClick={() => scrollTo('invoices')}
          />
          <NavButton
            Icon={Users}
            label="Peers"
            testId="nav-peers"
            count={state.peers.length}
            active={activeSection === 'peers'}
            onClick={() => scrollTo('peers')}
          />
          <NavButton
            Icon={Factory}
            label="Factories"
            testId="nav-factories"
            count={state.factories.length}
            active={activeSection === 'factories'}
            onClick={() => scrollTo('factories')}
          />
          <NavButton
            Icon={RadioTower}
            label="Watchtower"
            testId="nav-watchtower"
            count={state.watchtower.alerts.length}
            active={activeSection === 'watchtower'}
            onClick={() => scrollTo('watchtower')}
          />
          <NavButton
            Icon={Bell}
            label="Events"
            testId="nav-events"
            count={state.events.length}
            active={activeSection === 'events'}
            onClick={() => scrollTo('events')}
          />
        </nav>

        <div className="node-card">
          <span>Pubkey</span>
          <strong>{shortHex(state.pubkey) || '—'}</strong>
          <small>{state.node_id}</small>
        </div>
        <div className="node-card">
          <span>State file</span>
          <strong>{state.state_path ? state.state_path.split('/').pop() : 'not loaded'}</strong>
          <small>{state.state_path || '—'}</small>
        </div>

        <div className="coverage">
          <div className="coverage-top">
            <span>Runbook</span>
            <strong>{flowDataLoaded ? `${completedCount}/${state.required_flows.length}` : 'not loaded'}</strong>
          </div>
          <div className="meter">
            <span style={{ width: `${flowCoverage}%` }} />
          </div>
          <small>{flowDataLoaded ? (state.missing_flows.length === 0 ? 'All actions recorded' : `${state.missing_flows.length} actions remaining`) : 'Waiting for Hub API'}</small>
        </div>
      </aside>
      {commandOpen && (
        <CommandPalette
          busy={busy}
          onClose={() => setCommandOpen(false)}
          onRefresh={() => {
            setCommandOpen(false);
            void runAction('Refresh', refresh);
          }}
          onSearch={() => {
            setCommandOpen(false);
            document.querySelector<HTMLInputElement>('[data-testid="operator-search"]')?.focus();
          }}
          onOpenAction={panel => {
            setCommandOpen(false);
            selectAction(panel);
          }}
          onScroll={section => {
            setCommandOpen(false);
            scrollTo(section);
          }}
        />
      )}

      <section className="workspace" ref={workspaceRef}>
        <header className="topbar" id={sectionIds.overview}>
          <div>
            <h1>Morph Node <span className={`network-badge ${state.network}`}><span className="dot" />{state.network}</span></h1>
            <p>{status} · {lastRefreshLabel(lastRefreshMs, clockMs)} · {liveLabel(liveMode)}</p>
          </div>
          <div className="topbar-status">
            <StatusPill tone={rpcTone(state.rpc.status)} icon={<ShieldCheck size={15} />} label={rpcLabel(state)} title={rpcDetail(state)} />
            <StatusPill tone={authRequired && !requiresToken ? 'good' : 'warn'} icon={<ShieldCheck size={15} />} label={authRequired ? 'auth required' : 'loopback only'} />
            <StatusPill tone={liveTone(liveMode)} icon={<RadioTower size={15} />} label={liveLabel(liveMode)} />
            <StatusPill tone={evidence.localOnlyRecords > 0 ? 'warn' : evidence.watchtowerAlerts > 0 ? 'good' : 'neutral'} icon={<ShieldCheck size={15} />} label={evidenceStatusLabel(evidence)} />
            <StatusPill tone="neutral" icon={<Boxes size={15} />} label={state.rpc.tip_height == null ? 'tip unavailable' : `tip ${state.rpc.tip_height}`} />
            <button className={`icon-button ${busy ? 'spinning' : ''}`} title="Refresh from API" data-testid="hub-refresh" onClick={() => runAction('Refresh', refresh)} disabled={busy}>
              <RefreshCw size={16} />
            </button>
          </div>
        </header>

        <NodeInfoStrip state={state} flowDataLoaded={flowDataLoaded} />

        {error && (
          <div className="error banner" role="alert">
            <AlertTriangle size={15} />
            <span>{error}</span>
            <button type="button" title="Dismiss error" aria-label="Dismiss error" onClick={() => setError('')}><X size={13} /></button>
          </div>
        )}
        {requiresToken && (
          <form className="auth-banner" onSubmit={submitApiToken}>
            <ShieldCheck size={15} />
            <label>
              Morph Hub API token
              <input
                data-testid="api-token-input"
                type="password"
                value={tokenDraft}
                onChange={event => setTokenDraft(event.target.value)}
                autoComplete="off"
              />
            </label>
            <button data-testid="api-token-submit" disabled={!tokenDraft.trim() || busy}>Unlock API</button>
          </form>
        )}
        <div className={`provenance-banner ${evidence.localOnlyRecords > 0 ? 'local' : evidence.watchtowerAlerts > 0 ? 'connected' : 'local'}`} data-testid="provenance-banner">
          <ShieldCheck size={15} />
          <div>
            <strong>
              {evidence.localOnlyRecords > 0
                ? 'State-file records are local only'
                : evidence.watchtowerAlerts > 0
                  ? 'Watchtower evidence loaded'
                  : 'No record evidence loaded'}
            </strong>
            <span>{evidenceBannerText(state, evidence)}</span>
          </div>
        </div>

        <section className="metric-grid">
          <Metric label="Recorded channel value" value={totals.channelValue} icon={<Landmark size={16} />} />
          <Metric label="Sponsor budget" value={formatAmount(totals.sponsorBudget, { kind: 'ckb' })} icon={<WalletCards size={16} />} />
          <Metric label="Settling states" value={String(totals.settlingStates)} icon={<AlertTriangle size={16} />} tone={totals.settlingStates ? 'warn' : 'base'} />
          <Metric label="Recorded factory reserve" value={totals.factoryReserve} icon={<Factory size={16} />} />
        </section>

        <FlowPanel state={state} onOpenAction={selectAction} busy={busy} />

        <AcceptancePanel state={state} evidence={evidence} flowDataLoaded={flowDataLoaded} liveMode={liveMode} />

        <ModelBoundaryPanel model={state.model ?? emptyState.model} />

        <OperationSearch
          query={recordQuery}
          onQueryChange={setRecordQuery}
          active={searchActive}
          matchedCount={matchedRecordCount}
          totalCount={totalRecordCount}
          breakdown={recordBreakdown}
        />

        <section className="content-grid">
          <div id={sectionIds.channels}>
            <ChannelTable
              channels={filteredChannels}
              totalCount={orderedChannels.length}
              searchActive={searchActive}
              runAction={runAction}
              busy={busy}
              canWrite={canWrite}
              onOpenAction={() => selectAction('channel')}
            />
          </div>
          <div id={sectionIds.invoices}>
            <InvoicePanel invoices={filteredInvoices} totalCount={state.invoices.length} searchActive={searchActive} onOpenAction={() => selectAction('invoice')} nowMs={clockMs} />
          </div>
          <div id={sectionIds.peers}>
            <PeerPanel state={state} peers={filteredPeers} totalCount={orderedPeers.length} searchActive={searchActive} runAction={runAction} busy={busy} onOpenAction={() => selectAction('peer')} />
          </div>
          <div id={sectionIds.factories}>
            <FactoryPanel
              factories={filteredFactories}
              totalCount={orderedFactories.length}
              searchActive={searchActive}
              runAction={runAction}
              busy={busy}
              canWrite={canWrite}
              onOpenAction={() => selectAction('factory')}
              onMaterialise={openFactoryMaterialise}
            />
          </div>
          <div id={sectionIds.watchtower}>
            <WatchtowerPanel watchtower={state.watchtower} alerts={filteredWatchtowerAlerts} totalCount={orderedWatchtowerAlerts.length} searchActive={searchActive} onOpenAction={() => selectAction('state')} />
          </div>
          <div id={sectionIds.events}>
            <EventPanel events={filteredEvents} totalCount={orderedEvents.length} searchActive={searchActive} onRefresh={() => runAction('Refresh', refresh)} busy={busy} />
          </div>
        </section>
      </section>

      <aside className="action-drawer">
        <div className="drawer-head">
          <div>
            <span>Operate</span>
            <strong>{activeActionLabel}</strong>
          </div>
          <button
            type="button"
            className="drawer-toggle"
            onClick={toggleDrawerCollapsed}
            aria-label={drawerCollapsed ? 'Expand action drawer' : 'Collapse action drawer'}
            title={drawerCollapsed ? 'Expand action drawer' : 'Collapse action drawer'}
            data-testid="drawer-collapse-toggle"
          >
            {drawerCollapsed ? <PanelRightOpen size={15} /> : <PanelRightClose size={15} />}
          </button>
          <small>Writes local Hub state; chain evidence is shown separately.</small>
        </div>
        <div className="drawer-tabs">
          {actionItems.map(({ key, label, Icon }) => (
            <button
              className={activeAction === key ? 'selected' : ''}
              key={key}
              onClick={() => selectAction(key)}
              title={label}
              aria-label={label}
              data-testid={`action-${key}`}
            >
              <Icon size={15} />
            </button>
          ))}
        </div>
        {activeAction === 'peer' && <PeerActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'invoice' && <InvoiceActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'channel' && <ChannelActions state={state} runAction={runAction} busy={busy} />}
        {activeAction === 'factory' && <FactoryActions state={state} runAction={runAction} busy={busy} target={factoryActionTarget} />}
        {activeAction === 'state' && <StateActions state={state} runAction={runAction} busy={busy} />}
      </aside>
      <ToastViewport toasts={toasts} onDismiss={dismissToast} />
    </main>
  );
}

function initialDrawerCollapsed(): boolean {
  if (typeof window === 'undefined') return false;
  const stored = sessionStorage.getItem(DRAWER_COLLAPSED_STORAGE_KEY);
  if (stored != null) return stored === 'true';
  return window.innerWidth < 1280 && window.innerWidth > 1120;
}

function initialActionPanel(): ActionPanel {
  if (typeof window === 'undefined') return 'invoice';
  const stored = sessionStorage.getItem(ACTIVE_ACTION_STORAGE_KEY);
  return actionItems.some(item => item.key === stored) ? stored as ActionPanel : 'invoice';
}

function initialSection(): SectionKey {
  if (typeof window === 'undefined') return 'overview';
  const hash = window.location.hash.replace(/^#/, '');
  return (Object.keys(sectionIds) as SectionKey[]).find(key => sectionIds[key] === hash) ?? 'overview';
}

function NavButton({
  Icon,
  label,
  testId,
  count,
  active,
  onClick,
}: {
  Icon: LucideIcon;
  label: string;
  testId: string;
  count?: number;
  active?: boolean;
  onClick: () => void;
}) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} data-testid={testId} onClick={onClick}>
      <Icon size={16} />
      <span className="label">{label}</span>
      {count != null && count > 0 && <span className="count">{count}</span>}
    </button>
  );
}

function StatusPill({
  icon,
  label,
  tone,
  title,
}: {
  icon: React.ReactNode;
  label: string;
  tone: 'good' | 'neutral' | 'warn' | 'bad';
  title?: string;
}) {
  return <span className={`status-pill ${tone}`} title={title || label}>{icon}{label}</span>;
}

function ToastViewport({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div className="toast-stack" aria-live="polite" aria-atomic="false">
      {toasts.map(toast => (
        <article className={`toast ${toast.tone}`} key={toast.id}>
          <div>
            <strong>{toast.title}</strong>
            {toast.body && <small>{toast.body}</small>}
          </div>
          <button type="button" title="Dismiss notification" aria-label="Dismiss notification" onClick={() => onDismiss(toast.id)}>
            <X size={13} />
          </button>
        </article>
      ))}
    </div>
  );
}

function CommandPalette({
  busy,
  onClose,
  onRefresh,
  onSearch,
  onOpenAction,
  onScroll,
}: {
  busy: boolean;
  onClose: () => void;
  onRefresh: () => void;
  onSearch: () => void;
  onOpenAction: (panel: ActionPanel) => void;
  onScroll: (section: SectionKey) => void;
}) {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const dialogRef = useModalFocus(onClose);
  const commands: { label: string; detail: string; Icon: LucideIcon; action: () => void; disabled?: boolean }[] = [
    { label: 'Filter records', detail: 'Focus the global record search', Icon: Search, action: onSearch },
    { label: 'Refresh API state', detail: 'Fetch the latest Hub state', Icon: RefreshCw, action: onRefresh, disabled: busy },
    { label: 'Create invoice', detail: 'Open invoice controls', Icon: ReceiptText, action: () => onOpenAction('invoice') },
    { label: 'Connect peer', detail: 'Open peer controls', Icon: Users, action: () => onOpenAction('peer') },
    { label: 'Open channel', detail: 'Open channel controls', Icon: GitBranch, action: () => onOpenAction('channel') },
    { label: 'Open factory', detail: 'Open factory controls', Icon: Factory, action: () => onOpenAction('factory') },
    { label: 'State file', detail: 'Open state-file controls', Icon: FileJson, action: () => onOpenAction('state') },
    { label: 'Watchtower feed', detail: 'Jump to watchtower evidence', Icon: RadioTower, action: () => onScroll('watchtower') },
    { label: 'Events', detail: 'Jump to API event log', Icon: Bell, action: () => onScroll('events') },
  ];
  const tokens = queryTokens(query);
  const visibleCommands = commands.filter(command => {
    const text = `${command.label} ${command.detail}`.toLowerCase();
    return tokens.every(token => text.includes(token));
  });
  const boundedActiveIndex = Math.min(activeIndex, Math.max(visibleCommands.length - 1, 0));
  const runCommand = (index: number) => {
    const command = visibleCommands[index];
    if (command && !command.disabled) command.action();
  };
  const onPaletteKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (visibleCommands.length === 0) return;
      event.preventDefault();
      const direction = event.key === 'ArrowDown' ? 1 : -1;
      let next = boundedActiveIndex;
      do {
        next = (next + direction + visibleCommands.length) % visibleCommands.length;
      } while (visibleCommands[next].disabled && next !== boundedActiveIndex);
      setActiveIndex(next);
      dialogRef.current?.querySelector<HTMLButtonElement>(`[data-command-index="${next}"]`)?.focus();
      return;
    }
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      runCommand(boundedActiveIndex);
    }
  };

  return (
    <div className="modal-backdrop command-backdrop" role="presentation" onMouseDown={onClose}>
      <div ref={dialogRef} className="command-dialog" role="dialog" aria-modal="true" aria-labelledby="command-palette-title" tabIndex={-1} onKeyDown={onPaletteKeyDown} onMouseDown={event => event.stopPropagation()}>
        <div className="command-head">
          <div>
            <span>Command palette</span>
            <h3 id="command-palette-title">Operator actions</h3>
          </div>
          <button type="button" className="drawer-toggle" title="Close command palette" aria-label="Close command palette" onClick={onClose}>
            <X size={15} />
          </button>
        </div>
        <label className="command-search">
          <Search size={15} />
          <span className="sr-only">Filter operator actions</span>
          <input
            data-autofocus
            value={query}
            onChange={event => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            placeholder="Type an action…"
            aria-label="Filter operator actions"
          />
          <kbd>Esc</kbd>
        </label>
        <div className="command-list">
          {visibleCommands.map(({ label, detail, Icon, action, disabled }, index) => (
            <button
              type="button"
              className={index === boundedActiveIndex ? 'active' : ''}
              data-command-index={index}
              key={label}
              onMouseEnter={() => setActiveIndex(index)}
              onFocus={() => setActiveIndex(index)}
              onClick={action}
              disabled={disabled}
            >
              <Icon size={15} />
              <span>
                <strong>{label}</strong>
                <small>{detail}</small>
              </span>
            </button>
          ))}
          {visibleCommands.length === 0 && <div className="command-empty">No operator actions match “{query}”.</div>}
        </div>
      </div>
    </div>
  );
}

function NodeInfoStrip({
  state,
  flowDataLoaded,
}: {
  state: NodeState;
  flowDataLoaded: boolean;
}) {
  const flowsValue = flowDataLoaded ? `${state.completed_flows.length}/${state.required_flows.length}` : 'not loaded';
  const stateFile = state.state_path ? state.state_path.split('/').pop() || state.state_path : 'not loaded';
  return (
    <div className="node-info-strip" data-testid="node-info-strip">
      <NodeInfoPill Icon={Network} label="Pubkey" value={shortHex(state.pubkey) || 'not loaded'} title={state.pubkey} monospace />
      <NodeInfoPill Icon={Database} label="Node id" value={shortHex(state.node_id)} title={state.node_id} monospace />
      <span className="node-info-separator" />
      <NodeInfoPill Icon={Activity} label="Runbook" value={flowsValue} tone={flowDataLoaded && state.missing_flows.length === 0 ? 'good' : 'warn'} />
      <NodeInfoPill Icon={GitBranch} label="Channels" value={String(state.channels.length)} />
      <NodeInfoPill Icon={Users} label="Peers" value={String(state.peers.length)} />
      <NodeInfoPill Icon={ReceiptText} label="Invoices" value={String(state.invoices.length)} />
      <NodeInfoPill Icon={Factory} label="Factories" value={String(state.factories.length)} />
      <NodeInfoPill Icon={Boxes} label="Batches" value={String(state.conditional_batches.length)} />
      <NodeInfoPill Icon={FileJson} label="Recoveries" value={String(state.multi_asset_package_count ?? 0)} />
      <NodeInfoPill
        Icon={RadioTower}
        label="Watch"
        value={state.watchtower.configured ? String(state.watchtower.alerts.length) : 'off'}
        title={state.watchtower.alert_file || 'watchtower alert file not configured'}
        tone={state.watchtower.last_error ? 'bad' : state.watchtower.alerts.length > 0 ? 'warn' : 'neutral'}
      />
      <span className="node-info-separator" />
      <NodeInfoPill Icon={FileJson} label="State" value={stateFile} title={state.state_path} monospace />
    </div>
  );
}

function NodeInfoPill({
  Icon,
  label,
  value,
  tone = 'neutral',
  title,
  monospace = false,
}: {
  Icon: LucideIcon;
  label: string;
  value: string;
  tone?: 'good' | 'neutral' | 'warn' | 'bad';
  title?: string;
  monospace?: boolean;
}) {
  return (
    <span className={`node-info-pill ${tone}`} title={title || value}>
      <span className="node-info-icon"><Icon size={14} /></span>
      <span className="node-info-label">{label}</span>
      <strong className={monospace ? 'mono' : ''}>{value}</strong>
    </span>
  );
}

type EvidenceSummary = {
  localOnlyRecords: number;
  watchtowerAlerts: number;
  totalRecords: number;
};

function evidenceSummary(state: NodeState): EvidenceSummary {
  const provenances: RecordProvenance[] = [
    ...state.peers.map(record => record.provenance),
    ...state.channels.map(record => record.provenance),
    ...state.invoices.map(record => record.provenance),
    ...state.factories.map(record => record.provenance),
    ...state.events.map(record => record.provenance),
  ];
  return {
    localOnlyRecords: provenances.filter(provenance => provenance.chain_status === 'not_chain_verified').length,
    watchtowerAlerts: state.watchtower.alerts.length,
    totalRecords: provenances.length + state.watchtower.alerts.length,
  };
}

function evidenceStatusLabel(evidence: EvidenceSummary): string {
  if (evidence.localOnlyRecords > 0) return `${evidence.localOnlyRecords} local only`;
  if (evidence.watchtowerAlerts > 0) return `${evidence.watchtowerAlerts} evidenced`;
  return 'no records';
}

function evidenceBannerText(state: NodeState, evidence: EvidenceSummary): string {
  const watchtowerText = state.watchtower.configured
    ? `${evidence.watchtowerAlerts} watchtower alerts loaded.`
    : 'No watchtower evidence is configured.';
  if (evidence.localOnlyRecords > 0) {
    return `${evidence.localOnlyRecords} records are persisted locally and are not CKB devnet confirmation. ${watchtowerText}`;
  }
  if (evidence.watchtowerAlerts > 0) {
    return `All visible evidence comes from the configured watchtower alert file. ${watchtowerText}`;
  }
  return `${evidence.totalRecords} records loaded. ${watchtowerText}`;
}

function Metric({ label, value, icon, tone = 'base' }: { label: string; value: string; icon: React.ReactNode; tone?: 'base' | 'warn' }) {
  return (
    <article className={`metric ${tone}`}>
      <div className="metric-top">
        <span className="metric-icon">{icon}</span>
        <span className="metric-label">{label}</span>
      </div>
      <strong className="metric-value">{value}</strong>
    </article>
  );
}

function FlowPanel({
  state,
  onOpenAction,
  busy,
}: {
  state: NodeState;
  onOpenAction: (panel: ActionPanel) => void;
  busy: boolean;
}) {
  const flowDataLoaded = state.required_flows.length > 0;
  const flows = flowDataLoaded ? state.required_flows : (Object.keys(flowItems) as FlowKey[]);
  const complete = flowDataLoaded && state.missing_flows.length === 0;
  const doneSet = new Set(state.completed_flows);
  const orderedFlows = [...flows].sort((left, right) => {
    const byDone = Number(doneSet.has(left)) - Number(doneSet.has(right));
    return byDone || flowItems[left].label.localeCompare(flowItems[right].label);
  });
  return (
    <section className="flow-panel">
      <div className="section-head">
        <h2>Runbook</h2>
        <span className={`badge ${complete ? 'complete' : 'remaining'}`}>
          {!flowDataLoaded ? 'not loaded' : complete ? 'complete' : `${state.missing_flows.length} remaining`}
        </span>
      </div>
      <div className="flow-grid">
        {orderedFlows.map(flow => {
          const done = state.completed_flows.includes(flow);
          const item = flowItems[flow];
          const Icon = item.Icon;
          return (
            <article className={`flow-step ${done ? 'done' : ''}`} key={flow}>
              <span className="flow-dot">{done ? <BadgeCheck size={15} /> : <Icon size={14} />}</span>
              <div className="flow-main">
                <strong>{item.label}</strong>
                <small>{done ? 'Recorded in local Hub state' : item.detail}</small>
              </div>
              <button type="button" className="flow-action" onClick={() => onOpenAction(item.panel)} disabled={busy}>
                {done ? 'Open' : item.action}
              </button>
            </article>
          );
        })}
      </div>
    </section>
  );
}

type AcceptanceTone = 'good' | 'neutral' | 'warn' | 'bad';

type AcceptanceItem = {
  key: string;
  label: string;
  value: string;
  detail: string;
  tone: AcceptanceTone;
  Icon: LucideIcon;
};

function AcceptancePanel({
  state,
  evidence,
  flowDataLoaded,
  liveMode,
}: {
  state: NodeState;
  evidence: EvidenceSummary;
  flowDataLoaded: boolean;
  liveMode: LiveMode;
}) {
  const items = acceptanceItems(state, evidence, flowDataLoaded, liveMode);
  const blockers = items.filter(item => item.tone === 'bad').length;
  const warnings = items.filter(item => item.tone === 'warn').length;
  const badge = blockers > 0 ? `${blockers} blocked` : warnings > 0 ? `${warnings} warnings` : 'ready';

  return (
    <section className="acceptance-panel" data-testid="acceptance-panel">
      <div className="section-head">
        <h2>Devnet Acceptance</h2>
        <span className={`badge ${blockers > 0 || warnings > 0 ? 'remaining' : 'complete'}`}>{badge}</span>
      </div>
      <div className="acceptance-grid">
        {items.map(({ key, label, value, detail, tone, Icon }) => (
          <article className={`acceptance-card ${tone}`} key={key}>
            <span className="acceptance-icon"><Icon size={15} /></span>
            <div>
              <span>{label}</span>
              <strong>{value}</strong>
              <small>{detail}</small>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function acceptanceItems(
  state: NodeState,
  evidence: EvidenceSummary,
  flowDataLoaded: boolean,
  liveMode: LiveMode
): AcceptanceItem[] {
  const flowValue = flowDataLoaded ? `${state.completed_flows.length}/${state.required_flows.length}` : 'not loaded';
  const flowDetail = !flowDataLoaded
    ? 'The Hub API has not loaded the operator runbook yet.'
    : state.missing_flows.length === 0
      ? 'All required local operator flows are represented in Hub state.'
      : `${state.missing_flows.length} required local operator flows still need evidence.`;
  const flowTone: AcceptanceTone = !flowDataLoaded ? 'warn' : state.missing_flows.length === 0 ? 'good' : 'warn';

  const watchtowerValue = !state.watchtower.configured
    ? 'not configured'
    : state.watchtower.file_exists
      ? `${state.watchtower.alerts.length} alerts`
      : 'file pending';
  const watchtowerDetail = state.watchtower.last_error
    ? state.watchtower.last_error
    : !state.watchtower.configured
      ? 'No watchtower alert JSONL is attached to this Hub process.'
      : state.watchtower.file_exists
        ? 'The alert feed is available to prove watchtower observations.'
        : 'The configured alert feed has not been written yet.';
  const watchtowerTone: AcceptanceTone = state.watchtower.last_error
    ? 'bad'
    : state.watchtower.configured && state.watchtower.file_exists
      ? 'good'
      : state.watchtower.configured
        ? 'warn'
        : 'neutral';

  const provenanceValue = evidence.localOnlyRecords > 0
    ? `${evidence.localOnlyRecords} local only`
    : evidence.watchtowerAlerts > 0
      ? `${evidence.watchtowerAlerts} evidenced`
      : 'no records';
  const provenanceDetail = evidence.localOnlyRecords > 0
    ? 'State-file rows are useful for operation, but they are not CKB devnet confirmation.'
    : evidence.watchtowerAlerts > 0
      ? 'Visible evidence is coming from the configured watchtower alert feed.'
      : 'No local rows or watchtower alerts have been loaded into this console.';
  const provenanceTone: AcceptanceTone = evidence.localOnlyRecords > 0 ? 'warn' : evidence.watchtowerAlerts > 0 ? 'good' : 'neutral';

  return [
    {
      key: 'live-api',
      label: 'Live API',
      value: liveLabel(liveMode),
      detail: liveMode === 'offline'
        ? 'The console cannot refresh evidence until the Hub API is reachable.'
        : 'The console is refreshing state through SSE or polling.',
      tone: liveTone(liveMode),
      Icon: RadioTower,
    },
    {
      key: 'devnet-scope',
      label: 'Network scope',
      value: state.network,
      detail: 'This console is a devnet evidence surface, not a mainnet release certificate.',
      tone: state.network === 'devnet' ? 'good' : 'warn',
      Icon: Network,
    },
    {
      key: 'runbook-flows',
      label: 'Runbook flows',
      value: flowValue,
      detail: flowDetail,
      tone: flowTone,
      Icon: Activity,
    },
    {
      key: 'watchtower-feed',
      label: 'Watchtower feed',
      value: watchtowerValue,
      detail: watchtowerDetail,
      tone: watchtowerTone,
      Icon: ShieldCheck,
    },
    {
      key: 'record-provenance',
      label: 'Record provenance',
      value: provenanceValue,
      detail: provenanceDetail,
      tone: provenanceTone,
      Icon: FileJson,
    },
    {
      key: 'release-artefact',
      label: 'Release artefact',
      value: 'clean-tree CLI gate',
      detail: 'Production stateful artefacts pass only when devnet-stateful-assert sees a clean worktree and matching HEAD.',
      tone: 'warn',
      Icon: AlertTriangle,
    },
  ];
}

function OperationSearch({
  query,
  onQueryChange,
  active,
  matchedCount,
  totalCount,
  breakdown,
}: {
  query: string;
  onQueryChange: (query: string) => void;
  active: boolean;
  matchedCount: number;
  totalCount: number;
  breakdown: RecordBreakdown;
}) {
  const summary = active ? `${matchedCount}/${totalCount} records` : `${totalCount} records`;
  const chips = [
    `${breakdown.channels} channels`,
    `${breakdown.invoices} invoices`,
    `${breakdown.peers} peers`,
    `${breakdown.factories} factories`,
    `${breakdown.alerts} alerts`,
    `${breakdown.events} events`,
  ];
  return (
    <section className="operator-search" data-testid="operator-search-panel">
      <label>
        <Search size={15} />
        <span>Search records</span>
        <input
          data-testid="operator-search"
          value={query}
          onChange={event => onQueryChange(event.target.value)}
          aria-label="Search Hub records"
        />
      </label>
      <div className="operator-search-meta">
        <strong>{summary}</strong>
        <span>{chips.join(' · ')}</span>
        {query && (
          <button type="button" title="Clear search" aria-label="Clear search" data-testid="operator-search-clear" onClick={() => onQueryChange('')}>
            <X size={14} />
          </button>
        )}
      </div>
    </section>
  );
}
