import type { NodeState } from './domain';

export interface RestorePreview {
  confirmation_hash: string;
  allowed: boolean;
  current: RestoreStateSummary;
  candidate: RestoreStateSummary;
  ignored_completed_flows: string[];
  warnings: string[];
}

export interface RestoreStateSummary {
  peers: number;
  channels: number;
  factories: number;
  multi_asset_packages?: number;
  invoices: number;
  completed_flows: number;
  events: number;
  settling_channels: number;
}

const apiBase = import.meta.env.VITE_MORPH_HUB_API_URL ?? '';
const tokenStorageKey = 'morph-hub-api-token';
const requestTimeoutMs = 12_000;

let sessionApiToken = readStoredToken();

export class ApiRequestError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly retryAfterSeconds?: number;

  constructor({
    message,
    status,
    code,
    requestId,
    retryAfterSeconds,
  }: {
    message: string;
    status: number;
    code?: string;
    requestId?: string;
    retryAfterSeconds?: number;
  }) {
    super(message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export function hasApiToken(): boolean {
  return Boolean(currentApiToken());
}

export function setApiToken(token: string): void {
  sessionApiToken = token.trim();
  if (typeof window === 'undefined') return;
  if (sessionApiToken) {
    window.sessionStorage.setItem(tokenStorageKey, sessionApiToken);
  } else {
    window.sessionStorage.removeItem(tokenStorageKey);
  }
}

export async function getState(): Promise<NodeState> {
  return request<NodeState>('/api/state');
}

export async function getStateFile(): Promise<unknown> {
  return request<unknown>('/api/state-file');
}

export async function previewStateFile(state: unknown): Promise<RestorePreview> {
  return request<RestorePreview>('/api/state-file/preview', {
    method: 'POST',
    body: JSON.stringify(state),
  });
}

export async function replaceStateFile(state: unknown, confirmationHash: string): Promise<NodeState> {
  return request<NodeState>('/api/state-file', {
    method: 'PUT',
    body: JSON.stringify({ state, confirmation_hash: confirmationHash }),
  });
}

export async function postAction(path: string, body?: unknown): Promise<NodeState> {
  return request<NodeState>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function getMultiAssetRecoveryPackage(packageId: string): Promise<Record<string, unknown>> {
  if (!/^0x[0-9a-f]{64}$/.test(packageId)) throw new Error('Invalid recovery package id');
  return request<Record<string, unknown>>(`/api/multi-asset-packages/${packageId}`);
}

export async function connectPeer(pubkey: string, alias: string): Promise<NodeState> {
  return postAction('/api/peers', { pubkey, alias });
}

export function openEventStream(): EventSource | null {
  if (currentApiToken() || typeof EventSource === 'undefined') return null;
  return new EventSource(`${apiBase}/api/events`);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const apiToken = currentApiToken();
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), requestTimeoutMs);
  if (init.body !== undefined) headers.set('content-type', 'application/json');
  if (apiToken) headers.set('authorization', `Bearer ${apiToken}`);
  try {
    const response = await fetch(`${apiBase}${path}`, { ...init, headers, signal: controller.signal });
    if (!response.ok) {
      throw await readError(response);
    }
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiRequestError({
        message: `Morph Hub API timed out after ${requestTimeoutMs / 1000} seconds.`,
        status: 0,
        code: 'request_timeout',
      });
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function readError(response: Response): Promise<ApiRequestError> {
  const text = await response.text();
  const headerRequestId = response.headers.get('x-morph-hub-request-id')?.trim() || undefined;
  const retryAfterHeader = response.headers.get('retry-after');
  const retryAfter = retryAfterHeader == null ? Number.NaN : Number(retryAfterHeader);
  const retryAfterSeconds = Number.isFinite(retryAfter) && retryAfter >= 0 ? retryAfter : undefined;
  if (!text) {
    return new ApiRequestError({
      message: `${response.status} ${response.statusText}`,
      status: response.status,
      requestId: headerRequestId,
      retryAfterSeconds,
    });
  }
  try {
    const parsed = JSON.parse(text) as { error?: string; code?: string; request_id?: string };
    const requestId = parsed.request_id?.trim() || headerRequestId;
    const detail = parsed.error || text;
    const diagnostic = [parsed.code, requestId ? `request ${requestId}` : ''].filter(Boolean).join(' · ');
    return new ApiRequestError({
      message: `${response.status} ${response.statusText}: ${detail}${diagnostic ? ` (${diagnostic})` : ''}`,
      status: response.status,
      code: parsed.code,
      requestId,
      retryAfterSeconds,
    });
  } catch {
    return new ApiRequestError({
      message: `${response.status} ${response.statusText}: ${text}`,
      status: response.status,
      requestId: headerRequestId,
      retryAfterSeconds,
    });
  }
}

function currentApiToken(): string {
  return sessionApiToken;
}

function readStoredToken(): string {
  if (typeof window === 'undefined') return '';
  return window.sessionStorage.getItem(tokenStorageKey)?.trim() ?? '';
}
