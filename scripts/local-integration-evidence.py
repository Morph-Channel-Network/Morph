#!/usr/bin/env python3
"""Connect the existing local candidate pipeline to current integration receipts.

This profile requalifies W1 plus current asset-bound conditions on a local no-value node.
Public export reconstructs approved fields; it never copies raw execution logs.
"""
import argparse
import hashlib
import gzip
import io
import tarfile
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


V = module('integration_rules', 'verify-integration-evidence.py')
Q = module('local_rules', 'verify-local-candidate.py')


def load(path):
    return V.decode(V.read(path.parent, path.name))


def write(path, value):
    with path.open('x', encoding='utf8') as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write('\n')


def sha_file(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def node_identity(path):
    V.require(path.is_file() and os.access(path, os.X_OK), 'node executable missing')
    version = subprocess.check_output([str(path), '--version'], timeout=10)
    V.require(0 < len(version) <= 4096, 'invalid node version output')
    return {'schema': 'morph.local_node_identity.v1', 'binary_sha256': sha_file(path),
            'version_sha256': V.digest(version), 'size_bytes': path.stat().st_size}



def source_schemas():
    def one(path, pattern):
        matches = re.findall(pattern, (ROOT / path).read_text())
        V.require(len(matches) == 1, 'schema source changed; review evidence mapping')
        return matches[0]
    return {
        'runtime': 'morph.runtime-store.v' + one('crates/morph-runtime-store/src/lib.rs', r'pub const SCHEMA_VERSION: u32 = ([0-9]+);'),
        'hub-version': 'morph.hub-api.v' + one('crates/morph-hub-api/src/mutation.rs', r'pub const API_VERSION: &str = "([0-9]+)";'),
        'gateway-version': 'morph.gateway-api.v' + one('crates/morph-payment-gateway/src/api.rs', r'pub const API_VERSION: &str = "([0-9]+)";'),
        'events': one('crates/morph-packages/src/events.rs', r'pub enum EventSchema \{\s*#\[serde\(rename = "([a-z0-9._-]+)"\)\]\s*Current,'),
        'signer': one('crates/morph-packages/src/signer_protocol.rs', r'pub const VERSION: &str = "([a-z0-9._-]+)";'),
    }


def profile(out, node):
    rel = out.relative_to(ROOT).as_posix()
    bindings = {'cargo-lock': 'Cargo.lock', 'rust-toolchain': 'rust-toolchain.toml',
                'deployment-manifest': 'release/factory-preproduction/contracts.json',
                'envelope': 'release/factory-preproduction/envelope.json',
                'w1-scope': 'docs/w1-acceptance.md',
                'conditional-scope': 'docs/conditional-batches.md',
                'node': rel + '/node-identity.json',
                'runtime': 'crates/morph-runtime-store/src/lib.rs',
                'runtime-sql': 'crates/morph-runtime-store/src/schema.sql',
                'hub-version': 'crates/morph-hub-api/src/mutation.rs',
                'gateway-version': 'crates/morph-payment-gateway/src/api.rs',
                'hub-api': 'crates/morph-hub-api/src/schema.rs',
                'gateway-api': 'crates/morph-payment-gateway/src/api_schema.rs',
                'events': 'crates/morph-packages/src/events.rs',
                'signer': 'crates/morph-packages/src/signer_protocol.rs',
                'fiber-pin': 'integrations/fiber-shadow/manifest.json',
                'fiber-patch': 'integrations/fiber-shadow/a5faac71-shadow.patch'}
    bindings.update({'elf-' + name: 'target/riscv64imac-unknown-none-elf/release/' + name
                     for name in V.SCRIPTS})
    gates = {}
    def gate(name, command, configuration, replay):
        gates[name] = {'required': True, 'command': command, 'configuration': configuration,
                       'faults': [], 'replay': replay, 'exclusion': ''}
    gate('ci', ['make', 'ci'], ['cargo-lock', 'rust-toolchain', 'envelope', 'w1-scope'], ['test-results'])
    gate('native', ['env', 'OUT_DIR=' + str(out / 'native'), 'CKB_BIN=' + str(node),
                    'scripts/devnet-current-e2e.sh'], ['node', 'deployment-manifest', 'envelope'], ['transactions', 'assertions'])
    for name, scenario in [('signer-lifecycle', 'lifecycle'), ('cooperative-close', 'close'), ('typed-conditions', 'typed')]:
        gate(name, ['env', 'OUT_DIR=' + str(out / name), 'CKB_BIN=' + str(node),
                    'FIBER_DIR=' + str(Path(os.environ.get('FIBER_SOURCE', ROOT.parent / 'fiber')).resolve()),
                    'SCENARIO=' + scenario, 'bash', 'scripts/devnet-external-signer-e2e.sh'],
             ['node', 'deployment-manifest', 'signer', 'envelope', 'conditional-scope'], ['roles'])
        gates[name]['faults'] = ['service-unavailable', 'request-expired', 'response-lost',
                                'caller-restart', 'cached-retry']
    gates['typed-conditions']['replay'].append('resolutions')
    gate('fuzz', ['python3', '-B', 'scripts/w1-acceptance.py', 'fuzz', '--output', str(out / 'fuzz')],
         ['cargo-lock', 'rust-toolchain'], ['campaigns'])
    gate('shadow-service', ['python3', '-B', 'scripts/w1-acceptance.py', 'shadow', '--output', str(out / 'shadow'),
                          '--node', str(node), '--fiber-source',
                          str(Path(os.environ.get('FIBER_SOURCE', ROOT.parent / 'fiber')).resolve())],
         ['node', 'fiber-pin', 'fiber-patch', 'deployment-manifest'], ['shadow'])
    gates['shadow-service']['faults'] = ['provider-restart', 'journal-busy', 'source-spent', 'chain-reorg']
    gate('contracts-package', ['make', 'package-contract-release'], ['deployment-manifest', 'envelope'], [])
    gate('desktop-package', ['make', 'package-desktop'], ['cargo-lock', 'rust-toolchain'], [])
    gate('qualification', ['python3', '-B', 'scripts/verify-local-candidate.py',
                          '--public-evidence', str(out / 'public-evidence'),
                          '--bundle', str(out / 'morph-current-custody.tar.gz'),
                          '--desktop-bundle', str(out / 'morph-desktop-linux-x86_64.tar.gz'),
                          '--ci-receipt', str(out / 'ci-receipt.json')], ['envelope'], ['qualified-artifacts'])
    exclusions = {
        'independent-review': 'Owner excluded independent review from local no-value qualification; no attestation claimed.',
        'public-network': 'Owner excluded public-network evidence from local no-value qualification; no measurement claimed.',
        'live-routing': 'Nonforwarding shadow only; routed payments/provider-loss automation belong to later #38/#40 scope.',
        'future-clients': 'Current endpoint contracts and native CLI are qualified; new close GUI/HSM adapters and unexposed endpoints are future product work.',
    }
    for name, reason in exclusions.items():
        gates[name] = {'required': False, 'command': ['external-evidence', name], 'configuration': [],
                       'faults': [], 'replay': [], 'exclusion': reason}
    schemas = source_schemas()
    plan = {'schema': 'morph.integration_evidence_plan.v1', 'scope': V.SCOPE,
            'bindings': bindings, 'schemas': schemas, 'gates': gates}
    V.plan_validate(plan)
    return plan


def prepare(out):
    V.require(not os.environ.get('EXTERNAL_RPC_URL'), 'local candidate baseline requires its owned fresh development node')
    out = out.resolve(strict=True)
    V.require(out.is_relative_to(ROOT / '.local-evidence') or out.is_relative_to(ROOT / 'target'),
              'candidate output must be under .local-evidence or target')
    requested = os.environ.get('CKB_BIN') or shutil.which('ckb')
    V.require(requested, 'set CKB_BIN to a development CKB executable')
    node = Path(requested).resolve(strict=True)
    identity = node_identity(node)
    write(out / 'node-identity.json', identity)
    pin = load(ROOT / 'integrations/fiber-shadow/manifest.json')
    V.require(pin['schema'] == 'morph.fiber_shadow_patch.v1' and pin['forwarding'] is False
              and re.fullmatch(r'[0-9a-f]{40}', pin['fiber_revision'])
              and pin['patch_sha256'] == sha_file(ROOT / 'integrations/fiber-shadow/a5faac71-shadow.patch'),
              'Fiber pin/patch mismatch')
    plan = profile(out, node)
    candidate = V.capture(plan)
    V.require(candidate['dirty'] is False, 'commit source before qualification')
    before = load(out / 'source-provenance.json')
    V.require(before['git_commit_full'] == candidate['source_commit'] and before['git_dirty'] is False
              and before['source_tree_sha256'] == candidate['source_tree_sha256'], 'source changed during artifact preparation')
    write(out / 'integration-plan.json', plan)
    write(out / 'integration-candidate.json', candidate)
    (out / 'gates').mkdir(mode=0o700)


def ci_receipt(out):
    candidate = load(out / 'integration-candidate.json')
    receipt = load(out / 'gates/ci/execution.json')
    raw = V.read(out, 'gates/ci/output.private.log')
    V.require(receipt['exit_code'] == 0 and receipt['source_unchanged'] is True and receipt['timed_out'] is False
              and receipt['candidate_sha256'] == V.digest(V.canonical(candidate))
              and receipt['command_sha256'] == V.digest(V.canonical(['make', 'ci']))
              and receipt['log_sha256'] == V.digest(raw), 'invalid CI execution')
    write(out / 'ci-receipt.json', {'schema': 'morph.local_ci_receipt.v1', 'command': ['make', 'ci'],
          'exit_code': 0, 'source_commit': candidate['source_commit'],
          'source_tree_sha256': candidate['source_tree_sha256'], 'tracked_clean_before': True,
          'source_unchanged': True, 'log_sha256': V.digest(raw)})


def w1_results(out, candidate):
    """Validate actual campaign semantics before promoting their receipts."""
    result = {'schema': 'morph.local_w1_results.v1', 'scope': V.SCOPE,
              'source_commit': candidate['source_commit'], 'signers': {}, 'fuzz': [], 'shadow': {},
              'typed_conditions': {}}
    for name, roles in [
        ('signer-lifecycle', {'root_exit': 4, 'root_creation': 4, 'update': 2,
                              'splice_creation': 4, 'splice_recovery': 4, 'splice_bridge': 4}),
        ('cooperative-close', {'root_exit': 4, 'root_creation': 4, 'cooperative_close': 8}),
        ('typed-conditions', {'root_exit': 2, 'root_creation': 2, 'update': 2}),
    ]:
        v = load(out / name / 'verification.json')
        V.require(v['passed'] is True and v['source_unchanged'] is True
                  and v['source_dirty'] is False and v['roles'] == roles, 'incomplete signer campaign')
        count = sum(roles.values())
        V.require(v['completed_role_attempts'] == count and v['isolated_service_processes'] == count * 3
                  and v['key_using_processes'] == count * 2
                  and v['verified_fresh_caller_processes'] == count * 2, 'signer process coverage missing')
        expected = {'morph-cli', 'contracts.json', 'source-before.json', 'source-after.json', 'deployment.json'}
        expected |= {'shared.json', 'splice.json'} if name == 'signer-lifecycle' else {'typed.json'} if name == 'typed-conditions' else {'close-2.json', 'close-8.json'}
        V.require(set(v['sha256']) == expected
                  and v['sha256']['source-before.json'] == v['sha256']['source-after.json']
                  and v['sha256']['contracts.json'] == candidate['bindings']['deployment-manifest'],
                  'incomplete signer identity bindings')
        for file, checksum in v['sha256'].items():
            V.relative(file)
            V.require(sha_file(out / name / file) == checksum, 'signer artifact changed')
        source = load(out / name / 'source-before.json')
        V.require(source['head'] == candidate['source_commit']
                  and source['source_tree_sha256'] == candidate['source_tree_sha256'], 'signer candidate mismatch')
        result['signers'][name] = {'roles': roles, 'attempts': count,
                                  'verification_sha256': sha_file(out / name / 'verification.json')}
    names_source = (ROOT / 'crates/morph-xtask/src/fuzz/targets.rs').read_text()
    names = re.findall(r'"([a-z-]+)"', names_source.split('pub const NAMES:')[1].split('];', 1)[0])
    V.require(len(names) == len(set(names)) and len(names) >= 26, 'fuzz inventory drift')
    for seed in (1, 17, 332043276360):
        report = load(out / 'fuzz' / str(seed) / 'report.json')
        V.require(report['schema'] == 'morph.bounded_fuzz.v1' and report['status'] == 'pass'
                  and report['seed'] == seed and report['cases_per_target'] == 10000
                  and report['wall_seconds_per_target'] == 180
                  and [row['target'] for row in report['targets']] == names, 'incomplete fuzz campaign')
        targets = []
        for row in report['targets']:
            V.require(row['status'] == 'pass' and row['seed'] == seed and row['cases'] == 10000
                      and type(row['accepted']) is int and row['accepted'] > 0
                      and type(row['rejected']) is int and row['rejected'] > 0
                      and row['accepted'] + row['rejected'] == 10000, 'incomplete fuzz outcomes')
            targets.append({key: row[key] for key in ('target', 'cases', 'accepted', 'rejected')})
        result['fuzz'].append({'seed': seed, 'targets': targets,
                               'report_sha256': sha_file(out / 'fuzz' / str(seed) / 'report.json')})
    shadow = out / 'shadow' / 'native'
    v = load(shadow / 'verification.json')
    V.require(v['passed'] is True and v['forwarding'] is False and v['real_fiber_and_ckb'] is True
              and v['source_unchanged'] is True, 'shadow campaign did not pass')
    for file, checksum in v['sha256'].items():
        V.relative(file)
        V.require(sha_file(shadow / file) == checksum, 'shadow artifact changed')
    V.require(load(shadow / 'source-before.json')['morph']['head'] == candidate['source_commit'],
              'shadow candidate mismatch')
    pin = load(ROOT / 'integrations/fiber-shadow/manifest.json')
    hook = load(out / 'shadow/hook.json')
    V.require(hook['passed'] is True and hook['source_unchanged'] is True and hook['forwarding'] is False
              and hook['fiber_revision'] == pin['fiber_revision'] and hook['patch_sha256'] == pin['patch_sha256'],
              'shadow hook identity mismatch')
    summary = load(shadow / 'public-summary.json')
    fields = ['registered', 'morph_process_restarted', 'fiber_process_restart_acknowledged',
              'journal_busy_disabled', 'journal_released_reactivated', 'spent_custody_disabled',
              'orphaned_activation_disabled', 'exact_activation_replay_reactivated', 'reorg_preserved_backend_authority']
    V.require(all(summary[key] is True for key in fields) and summary['forwarding'] is False
              and summary['final_mirrors'] and all(m['state'] == 'disabled' and m['forwarding'] is False
                                                   for m in summary['final_mirrors']), 'shadow recovery missing')
    result['shadow'] = {key: summary[key] for key in fields}
    result['shadow'].update(forwarding=False, fiber_revision=pin['fiber_revision'],
                            patch_sha256=pin['patch_sha256'], binary_sha256=v['sha256']['fnn'],
                            verification_sha256=sha_file(shadow / 'verification.json'))
    # Full CI is already required. These sentinel results bind the non-native
    # acceptance tails to executed tests rather than merely listing definitions.
    required = ['multi_asset_backend_whole_consistent_snapshot_rollback_is_not_detectable_locally',
                'cooperative_close_consistent_whole_store_rollback_still_needs_external_freshness',
                'exact_shape_rejects_zero_token_rights_and_unwithdrawable_allocations',
                'lifetime_reservations_survive_restart_alternatives_closure_and_reorg',
                'bilateral_splice_peaks_and_factory_children_share_one_atomic_budget',
                'factory_multi_asset_reduced_release_rejects_retained_reserve_one_below_occupied_floor',
                'factory_multi_asset_reduced_release_rejects_replayed_frame_and_stale_before_header',
                'atomic_cas_replay_and_bounded_queries_share_memory_and_disk_semantics',
                'real_process_kill_before_commit_after_commit_and_after_acknowledgement',
                'actual_fsync_eio_and_enospc_never_acknowledge_partial_commit',
                'full_width_public_numbers_round_trip_without_json_number_coercion',
                'liveness_does_not_wait_for_store_and_busy_scope_is_not_ready',
                'unavailable_storage_recovers_only_after_the_real_file_is_accessible_again',
                'each_resource_has_one_fixed_diagnosis_without_hiding_other_resources',
                'publication_requires_full_fee_headroom_and_short_fresh_window',
                'real_supervisor_stop_expires_redacted_observation_without_mutating_evidence',
                'typed_conditions_maximum_eight_assets_sixty_four_conditions_and_script_bounds',
                'typed_batch_vm_resolves_above_u64_without_capacity_or_type_substitution',
                'current_bridge_excludes_pending_udt_from_its_type_without_reducing_other_assets',
                'conditional_preimages_match_fiber_hash_algorithm_vectors',
                'conditional_admission_preserves_identical_mature_batches_while_another_asset_resolves',
                'typed_conditions_fund_activate_and_exit_from_the_original_initial_recovery',
                'typed_conditions_splice_creation_recovery_activation_and_terminal_claims']
    log = V.read(out, 'gates/ci/output.private.log').decode()
    for name in required:
        V.require(re.search(r'^test (?:[\w:]+::)?' + re.escape(name) + r' \.\.\. ok$', log, re.M),
                  'required W1 test not executed: ' + name)
    result['typed_conditions'] = typed_results(out / 'typed-conditions')
    result['required_ci_tests'] = required
    write(out / 'w1-results.json', result)




def typed_expected(summary, family, asset_index):
    """Independent public-terms oracle; no wire parser or Core resolver here."""
    capability = summary['source']['capability']
    V.require(capability['kind'] == 'conditional', 'typed source lost conditional authority')
    selected = [b for b in capability['batches'] if b['batch_id'] == summary['batch_id']]
    V.require(len(selected) == 1 and selected[0]['asset'] == summary['asset'], 'typed source Batch mismatch')
    batch = selected[0]
    transfers = batch['transfers']
    V.require(len(transfers) == 8
              and {t['hash_algorithm'] for t in transfers} == {'ckb_blake2b', 'sha256'},
              'typed source misses algorithm/condition coverage')
    locks = sorted({transfers[0]['payer_lock_hash'], transfers[0]['payee_lock_hash']})
    V.require(len(locks) == 2, 'typed transfer has one party')
    amounts = [int(v) for v in batch['settled_amounts']]
    V.require(len(amounts) == 2 and len(batch['settled_capacities']) == 2, 'typed settlement shape')
    fulfills = 0
    for index, transfer in enumerate(transfers):
        V.require({transfer['payer_lock_hash'], transfer['payee_lock_hash']} == set(locks),
                  'typed transfer changes parties')
        quantity = int(transfer['amount'])
        V.require(0 < quantity < 2**128, 'typed transfer quantity')
        fulfill = family == 'fulfilled' or (asset_index % 2 == 1 and index % 3 == 0)
        fulfills += int(fulfill)
        recipient = transfer['payee_lock_hash'] if fulfill else transfer['payer_lock_hash']
        amounts[locks.index(recipient)] += quantity
    since = int(summary['input_since'])
    V.require((family == 'fulfilled' and since == 0) or
              (family == 'refunded_or_mixed' and since >= max(int(t['refund_after_block']) for t in transfers)),
              'typed branch clock does not authorize its decisions')
    expected = [{'capacity': capacity, 'amount': str(amount)}
                for capacity, amount in zip(batch['settled_capacities'], amounts)]
    actual = [{key: v[key] for key in ('capacity', 'amount')} for v in summary['resolved_values']]
    V.require(actual == expected, 'typed branch payouts differ from independent fulfill/refund oracle')
    return {'fulfill': fulfills, 'refund': 8 - fulfills}


def typed_results(directory):
    """Project verified quantities/status/resources; no preimages or private paths."""
    raw = load(directory / 'typed.json')
    terms = raw['conditional_settlement']
    V.require(raw['asset_count'] == terms['batch_count'] == 8
              and terms['conditions_per_batch'] == 8 and terms['provider_rpc_used'] is False
              and terms['all_payouts_verified'] is True
              and terms['participant_journals_unchanged'] is True, 'incomplete typed dimensions')
    result = {'asset_count': 8, 'conditions_per_asset': 8, 'provider_rpc_used': False,
              'participant_journals_unchanged': True, 'branches': {}}
    terminal = raw['finalise']
    metrics = terminal['metrics']
    V.require(terminal['canonical_confirmed'] is True and terminal['status'] == 'Committed'
              and re.fullmatch(r'0x[0-9a-f]{64}', terminal['tx_hash'])
              and type(metrics['estimated_cycles']) is int and 0 < metrics['estimated_cycles'] <= 70000000
              and type(metrics['tx_size_bytes']) is int and 0 < metrics['tx_size_bytes'] <= 500000,
              'typed terminal transaction is unqualified')
    result['terminal'] = {'transaction_hash': terminal['tx_hash'],
                          'estimated_cycles': metrics['estimated_cycles'],
                          'tx_size_bytes': metrics['tx_size_bytes']}
    identities = []
    for name in ('fulfilled', 'refunded_or_mixed'):
        rows = terms[name]
        V.require(type(rows) is list and len(rows) == 8, 'missing typed resolutions')
        projected = []
        assets = []
        for asset_index, row in enumerate(rows):
            op, summary = row['operation'], row['summary']
            V.require(op['status']['state'] == 'finalised' and op['canonical_confirmations'] >= 4
                      and op['required_depth'] == 4
                      and row['canonical_payouts_verified'] is True
                      and row['exact_retry_did_not_rebroadcast'] is True
                      and row['participant_journals_unchanged'] is True,
                      'typed resolution lacks canonical evidence')
            V.require(summary['asset']['kind'] == 'xudt' and summary['transfer_count'] == 8
                      and len(summary['resolved_values']) == 2,
                      'missing typed payout values')
            asset = summary['asset']['type_hash']
            V.require(re.fullmatch(r'0x[0-9a-f]{64}', asset), 'invalid typed identity')
            assets.append(asset)
            values = summary['resolved_values']
            for value in values:
                for key in ('capacity', 'amount'):
                    V.require(type(value[key]) is str and re.fullmatch(r'0|[1-9][0-9]*', value[key]),
                              'noncanonical typed quantity')
                V.require(0 < int(value['capacity']) < 2**64 and 0 <= int(value['amount']) < 2**128,
                          'typed payout overflow')
            V.require(sum(int(v['amount']) for v in values) == int(summary['total_amount']),
                      'typed payout conservation mismatch')
            V.require(re.fullmatch(r'0x[0-9a-f]{64}', op['transaction_hash'])
                      and re.fullmatch(r'[0-9a-f]{64}', op['operation_id']), 'invalid typed operation identity')
            cost = op['preflight']
            V.require(type(cost['estimated_cycles']) is int and type(cost['tx_size_bytes']) is int
                      and 0 < cost['estimated_cycles'] <= 70000000 and 0 < cost['tx_size_bytes'] <= 500000,
                      'typed resolution resource envelope exceeded')
            decisions = typed_expected(summary, name, asset_index)
            projected.append({'transaction_hash': op['transaction_hash'], 'asset_type_hash': asset,
                              'decisions': decisions,
                              'canonical_confirmations': op['canonical_confirmations'],
                              'payouts': [{key: value[key] for key in ('capacity', 'amount')} for value in values],
                              'estimated_cycles': cost['estimated_cycles'],
                              'tx_size_bytes': cost['tx_size_bytes']})
            identities.append(op['operation_id'])
        V.require(len(set(assets)) == 8, 'duplicate typed batch')
        result['branches'][name] = projected
    V.require([row['asset_type_hash'] for row in result['branches']['fulfilled']]
              == [row['asset_type_hash'] for row in result['branches']['refunded_or_mixed']],
              'replacement branch changes asset identities')
    orphaned = terms['orphaned_fulfillments']
    V.require(len(orphaned) == 8 and len(set(identities)) == 16, 'missing independent typed claims')
    for row in orphaned:
        V.require(row['operation']['status']['state'] == 'reorged'
                  and row['operation']['canonical_confirmations'] == 0
                  and row['depth_reached'] is False, 'orphaned claim retained confirmation credit')
    result['orphaned_claims_without_canonical_credit'] = 8
    return result


def assemble(plan, candidate, out):
    """All result sources here are known outputs of the baseline pipeline."""
    rows = {}
    def report(path):
        return {path: V.digest(V.read(out, path))}
    replay = {
        'ci': {'test-results': {'report': 'public-evidence/ci-results.json', 'pointer': '/result_lines'}},
        'native': {'transactions': {'report': 'public-evidence/transactions.json', 'pointer': '/transactions'},
                   'assertions': {'report': 'public-evidence/acceptance.json', 'pointer': '/scenarios'}},
        'qualification': {'qualified-artifacts': {'report': 'qualification.json', 'pointer': '/counts'}},
        'signer-lifecycle': {'roles': {'report': 'signer-lifecycle/verification.json', 'pointer': '/roles'}},
        'cooperative-close': {'roles': {'report': 'cooperative-close/verification.json', 'pointer': '/roles'}},
        'typed-conditions': {'roles': {'report': 'typed-conditions/verification.json', 'pointer': '/roles'},
                             'resolutions': {'report': 'w1-results.json', 'pointer': '/typed_conditions'}},
        'fuzz': {'campaigns': {'report': 'w1-results.json', 'pointer': '/fuzz'}},
        'shadow-service': {'shadow': {'report': 'w1-results.json', 'pointer': '/shadow'}},
    }
    for name, gate in plan['gates'].items():
        if not gate['required']:
            continue
        path = 'gates/' + name + '/execution.json'
        receipt = load(out / path)
        refs = replay.get(name, {})
        reports = report(path)
        for ref in refs.values():
            reports.update(report(ref['report']))
        rows[name] = {key: receipt[key] for key in ('candidate_sha256', 'command_sha256', 'configuration',
                                                   'started_at', 'finished_at', 'exit_code')}
        rows[name].update(status='pass', faults=gate['faults'], replay=refs, reports=reports, execution=path, reason='')
    start = min(row['started_at'] for row in rows.values())
    end = max(row['finished_at'] for row in rows.values())
    for name, gate in plan['gates'].items():
        if gate['required']:
            continue
        rows[name] = {'status': 'deferred', 'candidate_sha256': V.digest(V.canonical(candidate)),
                      'command_sha256': V.digest(V.canonical(gate['command'])), 'configuration': {},
                      'faults': [], 'replay': {}, 'reports': {}, 'execution': None,
                      'started_at': start, 'finished_at': start, 'exit_code': None, 'reason': gate['exclusion']}
    return {'schema': 'morph.integration_evidence.v1', 'scope': V.SCOPE,
            'candidate_sha256': V.digest(V.canonical(candidate)), 'started_at': start,
            'finished_at': end, 'gates': rows}


def finish(out):
    plan, candidate = load(out / 'integration-plan.json'), load(out / 'integration-candidate.json')
    node_arg = plan['gates']['native']['command'][2]
    V.require(node_arg.startswith('CKB_BIN='), 'unexpected node command')
    V.require(node_identity(Path(node_arg.removeprefix('CKB_BIN='))) == load(out / 'node-identity.json'),
              'node binary changed during qualification')
    # Do not accept a weakened caller-supplied baseline plan.
    V.require(plan == profile(out, Path(node_arg.removeprefix('CKB_BIN='))), 'baseline plan changed')
    public = Q.verify_public(out / 'public-evidence')
    qreceipt = load(out / 'gates/qualification/execution.json')
    qraw = V.read(out, 'gates/qualification/output.private.log')
    V.require(V.digest(qraw) == qreceipt['log_sha256'], 'qualification output changed')
    qualified = V.decode(qraw)
    V.require(qualified['schema'] == 'morph.local_candidate_qualification.v1' and qualified['status'] == 'passed'
              and qualified['source_commit'] == candidate['source_commit']
              and qualified['source_tree_sha256'] == candidate['source_tree_sha256']
              and qualified['real_assets_allowed'] is False and qualified['release_admitted'] is False,
              'qualification result mismatch')
    V.require(public['ci-results.json']['original_log_sha256'] == load(out / 'gates/ci/execution.json')['log_sha256'],
              'CI public result does not match executed output')
    V.require(qualified['public_evidence_index_sha256'] == sha_file(out / 'public-evidence/SHA256SUMS')
              and qualified['contract_bundle_sha256'] == sha_file(out / 'morph-current-custody.tar.gz')
              and qualified['native_desktop']['bundle_sha256'] == sha_file(out / 'morph-desktop-linux-x86_64.tar.gz'),
              'qualified artifact changed')
    write(out / 'qualification.json', qualified)
    w1_results(out, candidate)
    manifest = assemble(plan, candidate, out)
    result = V.validate(plan, candidate, manifest, out, V.capture(plan))
    write(out / 'integration-index.json', manifest)
    write(out / 'integration-validation.json', result)
    export_index(plan, candidate, manifest, result, out)
    V.require(V.same_candidate(V.capture(plan), candidate), 'candidate changed during export')
    bundle_public(out, qualified['public_evidence_index_sha256'])


def export_index(plan, candidate, manifest, result, out):
    """Public metadata only. Original private reports remain local references."""
    directory = out / 'integration-public'
    directory.mkdir(mode=0o700)
    gates = {}
    for name, row in manifest['gates'].items():
        # Names are closed by the baseline profile check in finish, not report content.
        gates[name] = {key: row[key] for key in ('status', 'started_at', 'finished_at', 'exit_code', 'command_sha256')}
        gates[name]['execution_sha256'] = row['reports'].get(row['execution']) if row['execution'] else None
        gates[name]['report_sha256'] = sorted(row['reports'].values())
        gates[name]['replay'] = {}
        for family, reference in row['replay'].items():
            source = reference['report']
            projected = source == 'qualification.json'
            runtime = source == 'w1-results.json' or name in ('signer-lifecycle', 'cooperative-close', 'typed-conditions')
            public_path = ('integration/runtime-results.json' if runtime else
                           'integration/artifact-results.json' if projected else 'native/' + Path(source).name)
            public_pointer = ('/signers/' + name + '/roles') if family == 'roles' else reference['pointer']
            gates[name]['replay'][family] = {'report': public_path, 'pointer': public_pointer,
                                           'source_report_sha256': row['reports'][source], 'projected': projected or runtime}
    value = {'schema': 'morph.public_integration_index.v1', 'profile': 'current-local-no-value',
             'scope': V.SCOPE, 'full_w1_qualified': True, 'conditional_udt_qualified': True, 'source_commit': candidate['source_commit'],
             'source_tree_sha256': candidate['source_tree_sha256'], 'bindings': candidate['bindings'],
             'schemas': candidate['schemas'], 'gates': gates, 'validation': result}
    write(directory / 'index.json', value)
    qualification = load(out / 'qualification.json')
    counts = {key: qualification['counts'][key] for key in
              ('native_cases', 'stateful_scenarios', 'evidence_assertions', 'audit_families')}
    for number in counts.values():
        V.number(number)
    projection = {'schema': 'morph.public_artifact_qualification.v1', 'counts': counts,
                  'scope': V.SCOPE, 'release_admitted': False, 'real_assets_allowed': False}
    for key in ('source_commit', 'contract_bundle_sha256', 'public_evidence_index_sha256', 'ci_receipt_sha256'):
        value = qualification[key]
        if key == 'source_commit':
            V.require(re.fullmatch(r'[0-9a-f]{40}', value), 'invalid public source')
        else:
            V.checksum(value)
        projection[key] = value
    write(directory / 'artifact-results.json', projection)
    write(directory / 'runtime-results.json', load(out / 'w1-results.json'))
    # These records are reconstructed/verified by this tool, never recursive copies.
    node = load(out / 'node-identity.json')
    write(directory / 'node.json', {key: node[key] for key in ('schema', 'binary_sha256', 'version_sha256', 'size_bytes')})
    pin = load(ROOT / 'integrations/fiber-shadow/manifest.json')
    write(directory / 'fiber.json', {'schema': 'morph.public_fiber_pin.v1', 'revision': pin['fiber_revision'],
                                   'patch_sha256': pin['patch_sha256'], 'runtime_campaign_executed': True})
    files = sorted(directory.iterdir())
    (directory / 'SHA256SUMS').write_text(''.join(sha_file(path) + '  ' + path.name + '\n' for path in files))



def bundle_public(out, expected_native_index):
    """Deterministic archive from exact allowlists and in-memory checked bytes."""
    allowed_native = {'checkpoint.json', 'contracts.json', 'publication-policy.json', 'transactions.json',
                      'acceptance.json', 'resource-budgets.json', 'ci-results.json', 'source-artifacts.json',
                      'README.md', 'SHA256SUMS'}
    allowed_integration = {'index.json', 'node.json', 'fiber.json', 'artifact-results.json', 'runtime-results.json', 'SHA256SUMS'}
    files = {}
    for directory, prefix, allowed in [(out / 'public-evidence', 'native', allowed_native),
                                       (out / 'integration-public', 'integration', allowed_integration)]:
        Q.verify_public(directory)
        names = {p.name for p in directory.iterdir()}
        V.require(names == allowed and all(p.is_file() for p in directory.iterdir()), 'unexpected public bundle member')
        raw_index = V.read(directory, 'SHA256SUMS')
        if prefix == 'native':
            V.require(V.digest(raw_index) == expected_native_index, 'qualified public index changed')
        hashes = Q.checksums(raw_index)
        for name in sorted(allowed):
            raw = V.read(directory, name)
            if name != 'SHA256SUMS':
                V.require(V.digest(raw) == hashes[name], 'public artifact changed while bundling')
            files[prefix + '/' + name] = raw
    V.require(sum(len(raw) for raw in files.values()) <= 8 * 1024 * 1024, 'public bundle too large')
    files['SHA256SUMS'] = ''.join(V.digest(raw) + '  ' + name + '\n' for name, raw in sorted(files.items())).encode()
    with (out / 'morph-integration-evidence.tar.gz').open('xb') as handle:
        with gzip.GzipFile(filename='', mode='wb', fileobj=handle, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for name, raw in sorted(files.items()):
                    info = tarfile.TarInfo('morph-integration-evidence/' + name)
                    info.size, info.mode, info.mtime = len(raw), 0o644, 0
                    archive.addfile(info, io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'ci-receipt', 'finish'])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve(strict=True)
    {'prepare': prepare, 'ci-receipt': ci_receipt, 'finish': finish}[args.action](out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'local integration evidence rejected: {error}') from error
