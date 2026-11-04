import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {afterEach,describe,expect,it,vi} from 'vitest';
import fixture from '../../../sdk/typescript/test/fixtures/multi-asset-root.json';
import conditionalFixture from '../../../sdk/typescript/test/fixtures/multi-asset-conditional-root.json';
import {RootFundingActions} from './actions';
import {emptyState,type NodeState,type RootFundingSummary} from './domain';
import {getRootFunding,postAction} from './api';
vi.mock('./api',async()=>({...await vi.importActual<typeof import('./api')>('./api'),getRootFunding:vi.fn(),postAction:vi.fn()}));
afterEach(()=>{cleanup();vi.clearAllMocks();});
function state(exit:number,creation:number):NodeState {
  const summary={...fixture.inspection,exit_signature_count:exit,creation_signature_count:creation,ready_to_export:exit===2&&creation===2} as RootFundingSummary;
  return {...emptyState,root_fundings:[summary],security:{...emptyState.security,auth_required:false}};
}
describe('public root funding coordination',()=>{
  it('shows signed pending terms and absolute refund policy before retaining conditional receipts',async()=>{
    const user=userEvent.setup();const current=state(2,0);
    current.root_fundings[0]={...conditionalFixture.inspection,exit_signature_count:2,creation_signature_count:0,ready_to_export:false} as RootFundingSummary;
    vi.mocked(getRootFunding).mockResolvedValue(conditionalFixture.collection);
    render(<RootFundingActions state={current} runAction={vi.fn()} busy={false}/>);
    await user.click(screen.getByRole('button',{name:/exit 2\/2/}));
    expect(screen.getByRole('heading',{name:'Conditional CKB settlement'})).toBeTruthy();
    expect(screen.getByText(/2000000000 shannons remain pending/)).toBeTruthy();
    expect(screen.getByText(/Refund to payer from absolute block 500/)).toBeTruthy();
    expect(screen.getByText(new RegExp(conditionalFixture.inspection.capability.transfers[0]!.payment_hash))).toBeTruthy();
    expect(screen.queryByText('Settlement: ordinary allocations.')).toBeNull();
  });
  it('gates creation and export on complete exit receipts and preserves exact quantities',async()=>{
    const user=userEvent.setup();let current=state(0,0);
    vi.mocked(getRootFunding).mockResolvedValue(fixture.collection);
    vi.mocked(postAction).mockImplementation(async()=>current);
    const runAction=vi.fn(async(_label:string,action:()=>Promise<NodeState>)=>{await action();});
    const view=render(<RootFundingActions state={current} runAction={runAction} busy={false}/>);
    await user.click(screen.getByRole('button',{name:/exit 0\/2/}));
    await waitFor(()=>expect((screen.getByTestId('root-draft-json') as HTMLTextAreaElement).value).toContain('morph.multi_asset_root_draft.v1'));
    expect((screen.getByRole('option',{name:'Root creation'}) as HTMLOptionElement).disabled).toBe(true);
    expect((screen.getByTestId('root-bundle-export') as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/does not establish a funded channel/)).toBeTruthy();
    expect(screen.getAllByText(new RegExp(fixture.inspection.payouts[0]!.allocations[0]!.amount)).length).toBeGreaterThan(0);
    fireEvent.change(screen.getByTestId('root-receipt-json'),{target:{value:JSON.stringify(fixture.exit_receipts[0])}});
    await user.click(screen.getByTestId('root-receipt-import'));
    await waitFor(()=>expect(postAction).toHaveBeenCalledWith(`/api/root-fundings/${fixture.inspection.transaction_hash}/signatures`,{target:'exit',receipt:fixture.exit_receipts[0]}));
    current=state(2,0);view.rerender(<RootFundingActions state={current} runAction={runAction} busy={false}/>);
    expect((screen.getByRole('option',{name:'Root creation'}) as HTMLOptionElement).disabled).toBe(false);
    await user.selectOptions(screen.getByTestId('root-receipt-target'),'creation');
    fireEvent.change(screen.getByTestId('root-receipt-json'),{target:{value:JSON.stringify(fixture.creation_receipts[0])}});
    await user.click(screen.getByTestId('root-receipt-import'));
    await waitFor(()=>expect(postAction).toHaveBeenLastCalledWith(`/api/root-fundings/${fixture.inspection.transaction_hash}/signatures`,{target:'creation',receipt:fixture.creation_receipts[0]}));
    current=state(2,2);view.rerender(<RootFundingActions state={current} runAction={runAction} busy={false}/>);
    vi.mocked(getRootFunding).mockResolvedValue(fixture.funding);
    await user.click(screen.getByTestId('root-bundle-export'));
    await waitFor(()=>expect(JSON.parse((screen.getByTestId('root-bundle-json') as HTMLTextAreaElement).value)).toEqual(fixture.funding));
    expect(screen.getByText(/Funding wallets still need to authorize/)).toBeTruthy();
  });
  it('keeps read-only coordination from posting public drafts or receipts',async()=>{
    const current=state(2,2);current.security={...current.security,auth_required:true,auth_mode:'scoped_bearer',auth_scopes:['read']};
    render(<RootFundingActions state={current} runAction={vi.fn()} busy={false}/>);
    fireEvent.change(screen.getByTestId('root-draft-json'),{target:{value:JSON.stringify(fixture.draft)}});
    expect((screen.getByTestId('root-draft-import') as HTMLButtonElement).disabled).toBe(true);
    fireEvent.submit(screen.getByTestId('root-draft-import').closest('form')!);
    expect(postAction).not.toHaveBeenCalled();
  });
});
