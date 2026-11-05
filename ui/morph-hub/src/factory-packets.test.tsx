import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import corpus from '../../../sdk/typescript/test/fixtures/factory-packets.json';
import { FactoryPacketInspector } from './factory-packets';

afterEach(cleanup);
function inspect(request: unknown, receipt?: unknown) {
  fireEvent.change(screen.getByTestId('factory-request-json'), { target: { value: JSON.stringify(request) } });
  if (receipt) fireEvent.change(screen.getByTestId('factory-signature-json'), { target: { value: JSON.stringify(receipt) } });
  fireEvent.click(screen.getByRole('button', { name: 'Inspect public request' }));
}
describe('current Factory public packet review', () => {
  it('shows exact Root custody, full decimal quantities and checked participant receipts', () => {
    const root = corpus.cases.find(item => item.name === 'root_funding')!;
    render(<FactoryPacketInspector />);
    inspect(root.request, root.signatures[0]);
    expect(screen.getByText('Public terms verified')).toBeTruthy();
    expect(screen.getByText(/Participant receipt matches the exact request/)).toBeTruthy();
    expect(screen.getByText(/State carrier 50000000000 shannons/)).toBeTruthy();
    expect(screen.getByText(/reserve 30000000000; business CKB 10000000000; token amount 0/)).toBeTruthy();
    expect(screen.getByText(/Native Core must verify complete Factory transition semantics/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /sign|submit|broadcast/i })).toBeNull();
  });
  it('shows withheld child delivery independently from valid public initial-exit terms', () => {
    const child = corpus.cases.find(item => item.name === 'reduced_child_missing_delivery')!;
    render(<FactoryPacketInspector />);
    inspect(child.request);
    expect(screen.getByText('Child delivery incomplete: 2 attestation(s) missing.')).toBeTruthy();
    expect(screen.getByText('Child 0: initial exit')).toBeTruthy();
    expect(screen.getByText(/State 1 · settling/)).toBeTruthy();
    expect(screen.getByText('Settlement: ordinary allocations.')).toBeTruthy();
    expect(screen.queryByText(/receipt matches the exact request/)).toBeNull();
  });
  it('rejects a replayed receipt and clears a previous successful review', () => {
    const root = corpus.cases.find(item => item.name === 'root_funding')!;
    render(<FactoryPacketInspector />);
    inspect(root.request, root.signatures[0]);
    expect(screen.getByTestId('factory-packet-inspection')).toBeTruthy();
    inspect(root.request, { ...root.signatures[0], request_id: `0x${'00'.repeat(32)}` });
    expect(screen.getByRole('alert').textContent).toContain('exact request/role/member mismatch');
    expect(screen.queryByTestId('factory-packet-inspection')).toBeNull();
  });
});
