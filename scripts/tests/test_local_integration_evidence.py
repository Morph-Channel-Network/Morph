"""Synthetic baseline wiring tests; no native qualification is claimed here."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import shutil
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('local_integration', ROOT / 'scripts/local-integration-evidence.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class LocalIntegrationTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'target').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='integration-wiring-test-', dir=ROOT / 'target')
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        self.plan = M.profile(self.out, Path('/synthetic/ckb'))
        self.candidate = {'schema': 'morph.integration_candidate.v1', 'scope': M.V.SCOPE,
                          'source_commit': '1' * 40, 'source_tree_sha256': '2' * 64,
                          'dirty': False, 'captured_at': 100,
                          'plan_sha256': M.V.digest(M.V.canonical(self.plan)),
                          'bindings': {name: '3' * 64 for name in self.plan['bindings']},
                          'schemas': self.plan['schemas']}
        M.write(self.out / 'integration-candidate.json', self.candidate)
        for name, gate in self.plan['gates'].items():
            if not gate['required']: continue
            directory = self.out / 'gates' / name
            directory.mkdir(parents=True)
            raw = b'synthetic raw log with PRIVATE-MARKER\n'
            (directory / 'output.private.log').write_bytes(raw)
            receipt = {'schema': 'morph.integration_execution.v1', 'gate': name,
                       'candidate_sha256': M.V.digest(M.V.canonical(self.candidate)),
                       'command_sha256': M.V.digest(M.V.canonical(gate['command'])),
                       'configuration': {key: self.candidate['bindings'][key] for key in gate['configuration']},
                       'started_at': 101, 'finished_at': 110, 'exit_code': 0,
                       'source_unchanged': True, 'timed_out': False, 'log_sha256': M.V.digest(raw)}
            M.write(directory / 'execution.json', receipt)
        public = self.out / 'public-evidence'
        public.mkdir()
        files = {'checkpoint.json': {}, 'contracts.json': {}, 'publication-policy.json': {},
                 'transactions.json': {'transactions': [{'synthetic': True}]},
                 'acceptance.json': {'scenarios': [{'synthetic': True}]},
                 'resource-budgets.json': {}, 'ci-results.json': {'result_lines': ['synthetic test result']},
                 'source-artifacts.json': {}}
        for name, value in files.items(): M.write(public / name, value)
        (public / 'README.md').write_text('Synthetic sanitized report fixture')
        self.checksums(public)
        self.qualification = {'schema': 'morph.local_candidate_qualification.v1', 'source_commit': '1' * 40,
                              'status': 'passed', 'counts': {'native_cases': 5, 'stateful_scenarios': 10,
                                                           'evidence_assertions': 99, 'audit_families': 11},
                              'contract_bundle_sha256': '4' * 64, 'ci_receipt_sha256': '5' * 64,
                              'public_evidence_index_sha256': M.sha_file(public / 'SHA256SUMS')}
        M.write(self.out / 'qualification.json', self.qualification)
        M.write(self.out / 'node-identity.json', {'schema': 'morph.local_node_identity.v1',
                                               'binary_sha256': '6' * 64, 'version_sha256': '7' * 64,
                                               'size_bytes': 123})
        self.runtime = {'schema': 'morph.local_w1_results.v1', 'scope': M.V.SCOPE,
                        'source_commit': '1' * 40, 'signers': {},
                        'fuzz': [{'seed': 1}], 'shadow': {'forwarding': False},
                        'typed_conditions': {'asset_count': 8}}
        for name in ('signer-lifecycle', 'cooperative-close', 'typed-conditions'):
            directory = self.out / name
            directory.mkdir()
            M.write(directory / 'verification.json', {'roles': {'synthetic': 1}})
            self.runtime['signers'][name] = {'roles': {'synthetic': 1}}
        M.write(self.out / 'w1-results.json', self.runtime)

    def checksums(self, path):
        names = sorted(p for p in path.iterdir() if p.name != 'SHA256SUMS')
        (path / 'SHA256SUMS').write_text(''.join(M.sha_file(p) + '  ' + p.name + '\n' for p in names))

    def assemble(self):
        index = M.assemble(self.plan, self.candidate, self.out)
        result = M.V.validate(self.plan, self.candidate, index, self.out, self.candidate, now=120)
        return index, result

    def export(self):
        index, result = self.assemble()
        M.export_index(self.plan, self.candidate, index, result, self.out)
        return index

    def test_current_plan_binds_real_schema_owners_and_excludes_unexecuted_work(self):
        self.assertEqual(self.plan['schemas']['events'], 'morph.event.v1')
        self.assertEqual(self.plan['schemas']['signer'], 'morph.participant_signer.v1')
        self.assertEqual(self.plan['schemas']['hub-version'], 'morph.hub-api.v1')
        self.assertEqual(self.plan['schemas']['runtime'], 'morph.runtime-store.v1')
        for name in ['independent-review', 'public-network', 'live-routing', 'future-clients']:
            self.assertFalse(self.plan['gates'][name]['required'])
            self.assertTrue(self.plan['gates'][name]['exclusion'])
        for name in ['signer-lifecycle', 'cooperative-close', 'typed-conditions', 'fuzz', 'shadow-service']:
            self.assertTrue(self.plan['gates'][name]['required'])
        self.assertEqual(self.plan['gates']['ci']['command'], ['make', 'ci'])
        self.assertIn('CKB_BIN=/synthetic/ckb', self.plan['gates']['native']['command'])

    def test_schema_extraction_rejects_owner_drift_instead_of_reusing_labels(self):
        with patch.object(Path, 'read_text', return_value='pub const VERSION: &str = "unexpected";'):
            with self.assertRaisesRegex(ValueError, 'schema source changed'): M.source_schemas()

    def test_typed_campaign_rejects_false_depth_duplicate_assets_and_leaking_private_fields(self):
        directory = self.out / 'typed-conditions'
        terms = {'batch_count': 8, 'conditions_per_batch': 8, 'provider_rpc_used': False,
                 'all_payouts_verified': True, 'participant_journals_unchanged': True,
                 'orphaned_fulfillments': [{'depth_reached': False, 'operation': {
                     'status': {'state': 'reorged'}, 'canonical_confirmations': 0}} for _ in range(8)]}
        for family, offset in [('fulfilled', 0), ('refunded_or_mixed', 8)]:
            terms[family] = [{'operation': {'operation_id': format(i + offset, '064x'),
                'transaction_hash': '0x' + format(i + offset, '064x'), 'status': {'state': 'finalised'},
                'canonical_confirmations': 4, 'required_depth': 4,
                'preflight': {'estimated_cycles': 1000, 'tx_size_bytes': 1000}},
                'summary': {'asset': {'kind': 'xudt', 'type_hash': '0x' + format(i + 1, '064x')},
                            'resolved_values': [{'capacity': '1000', 'amount': '4', 'private': 'PRIVATE-MARKER'} for _ in range(2)],
                            'transfer_count': 8, 'total_amount': '8'}, 'canonical_payouts_verified': True,
                'exact_retry_did_not_rebroadcast': True, 'participant_journals_unchanged': True,
                'preimage': 'PRIVATE-MARKER', 'operation_store': '/PRIVATE-MARKER'} for i in range(8)]
        for family in ('fulfilled', 'refunded_or_mixed'):
            for asset_index, row in enumerate(terms[family]):
                summary = row['summary']
                summary['batch_id'] = '0x' + format(asset_index + 1, '064x')
                summary['input_since'] = '0' if family == 'fulfilled' else '100'
                summary['source'] = {'capability': {'kind': 'conditional', 'batches': [{
                    'asset': summary['asset'], 'batch_id': summary['batch_id'],
                    'settled_amounts': ['0', '0'], 'settled_capacities': ['1000', '1000'],
                    'transfers': [{'amount': '1', 'payer_lock_hash': str(i % 2),
                                   'payee_lock_hash': str(1 - i % 2),
                                   'hash_algorithm': 'sha256' if i % 2 else 'ckb_blake2b',
                                   'refund_after_block': '100'} for i in range(8)]}]}}
                if family == 'refunded_or_mixed' and asset_index % 2:
                    summary['resolved_values'][0]['amount'] = '3'
                    summary['resolved_values'][1]['amount'] = '5'
        value = {'asset_count': 8, 'conditional_settlement': terms,
                 'finalise': {'canonical_confirmed': True, 'status': 'Committed',
                              'tx_hash': '0x' + 'f' * 64,
                              'metrics': {'estimated_cycles': 1000, 'tx_size_bytes': 1000}}}
        path = directory / 'typed.json'
        path.write_text(json.dumps(value))
        projection = M.typed_results(directory)
        self.assertEqual(projection['orphaned_claims_without_canonical_credit'], 8)
        self.assertNotIn('PRIVATE-MARKER', json.dumps(projection))
        for mutation in range(7):
            changed = copy.deepcopy(value)
            t = changed['conditional_settlement']
            if mutation == 0: t['provider_rpc_used'] = True
            elif mutation == 1: t['fulfilled'][0]['operation']['canonical_confirmations'] = 0
            elif mutation == 2: t['fulfilled'][1]['summary']['asset'] = t['fulfilled'][0]['summary']['asset']
            elif mutation == 3: t['fulfilled'][0]['summary']['resolved_values'][0]['amount'] = '-1'
            elif mutation == 4: t['orphaned_fulfillments'][0]['operation']['status']['state'] = 'finalised'
            elif mutation == 5: t['refunded_or_mixed'].pop()
            else:
                t['fulfilled'][0]['summary']['resolved_values'][0]['amount'] = '3'
                t['fulfilled'][0]['summary']['resolved_values'][1]['amount'] = '5'
            path.write_text(json.dumps(changed))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): M.typed_results(directory)

    def test_w1_cannot_complete_with_dirty_failed_or_partial_signer_coverage(self):
        path = self.out / 'signer-lifecycle/verification.json'
        roles = {'root_exit': 4, 'root_creation': 4, 'update': 2,
                 'splice_creation': 4, 'splice_recovery': 4, 'splice_bridge': 4}
        good = {'passed': True, 'source_unchanged': True, 'source_dirty': False, 'roles': roles,
                'completed_role_attempts': 22, 'isolated_service_processes': 66,
                'key_using_processes': 44, 'verified_fresh_caller_processes': 44,
                'sha256': {}}
        for key, changed in [('passed', False), ('source_unchanged', False), ('source_dirty', True),
                             ('roles', {'root_exit': 4}), ('completed_role_attempts', 21),
                             ('verified_fresh_caller_processes', 43), ('sha256', {})]:
            with self.subTest(key=key):
                value = dict(good)
                value[key] = changed
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError): M.w1_results(self.out, self.candidate)

    def test_ci_receipt_binds_merged_actual_log_and_rejects_changes(self):
        M.ci_receipt(self.out)
        row = M.load(self.out / 'ci-receipt.json')
        self.assertEqual(row['log_sha256'], M.sha_file(self.out / 'gates/ci/output.private.log'))
        (self.out / 'ci-receipt.json').unlink()
        (self.out / 'gates/ci/output.private.log').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'invalid CI execution'): M.ci_receipt(self.out)

    def test_assembled_baseline_validates_but_cannot_promote_missing_or_failed_gate(self):
        index, result = self.assemble()
        self.assertTrue(result['qualified_declared_plan'])
        self.assertEqual(index['gates']['live-routing']['status'], 'deferred')
        receipt = self.out / 'gates/native/execution.json'
        changed = M.load(receipt)
        changed['exit_code'] = 7
        receipt.write_text(json.dumps(changed))
        with self.assertRaises(ValueError): self.assemble()
        receipt.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)): self.assemble()

    def test_public_projection_never_copies_logs_argv_or_free_text(self):
        # Deliberate private garbage outside the allowlist must remain local.
        (self.out / 'active-signer.json').write_text('PRIVATE-MARKER')
        self.export()
        directory = self.out / 'integration-public'
        self.assertEqual({p.name for p in directory.iterdir()},
                         {'index.json', 'node.json', 'fiber.json', 'artifact-results.json', 'runtime-results.json', 'SHA256SUMS'})
        for path in directory.iterdir():
            self.assertNotIn(b'PRIVATE-MARKER', path.read_bytes())
            self.assertNotIn(b'/synthetic/ckb', path.read_bytes())
        index = M.load(directory / 'index.json')
        self.assertTrue(index['full_w1_qualified'])
        self.assertTrue(index['conditional_udt_qualified'])
        self.assertEqual(index['profile'], 'current-local-no-value')
        self.assertEqual(index['gates']['native']['replay']['transactions']['report'], 'native/transactions.json')
        M.Q.verify_public(directory)

    def test_archive_is_deterministic_allowlisted_and_replay_locations_resolve(self):
        self.export()
        expected = self.qualification['public_evidence_index_sha256']
        M.bundle_public(self.out, expected)
        bundle = self.out / 'morph-integration-evidence.tar.gz'
        original = bundle.read_bytes()
        with tarfile.open(bundle, 'r:gz') as archive:
            members = archive.getmembers()
            self.assertTrue(all(m.isfile() and m.mtime == 0 for m in members))
            content = {m.name.removeprefix('morph-integration-evidence/'): archive.extractfile(m).read() for m in members}
        hashes = M.Q.checksums(content['SHA256SUMS'])
        self.assertEqual(set(hashes), set(content) - {'SHA256SUMS'})
        for name, digest in hashes.items(): self.assertEqual(M.V.digest(content[name]), digest)
        self.assertNotIn(b'PRIVATE-MARKER', b''.join(content.values()))
        index = json.loads(content['integration/index.json'])
        for row in index['gates'].values():
            for ref in row['replay'].values():
                report = json.loads(content[ref['report']])
                for key in ref['pointer'].removeprefix('/').split('/'):
                    report = report[key]
                self.assertTrue(report)
        bundle.unlink()
        M.bundle_public(self.out, expected)
        self.assertEqual(bundle.read_bytes(), original)

    def stage_finish(self):
        M.write(self.out / 'integration-plan.json', self.plan)
        for name in ['morph-current-custody.tar.gz', 'morph-desktop-linux-x86_64.tar.gz']:
            (self.out / name).write_bytes(b'synthetic package, not a real deployment')
        public = self.out / 'public-evidence'
        row = M.load(public / 'ci-results.json')
        row['original_log_sha256'] = M.load(self.out / 'gates/ci/execution.json')['log_sha256']
        (public / 'ci-results.json').write_text(json.dumps(row))
        self.checksums(public)
        q = copy.deepcopy(self.qualification)
        q.update(source_tree_sha256=self.candidate['source_tree_sha256'], real_assets_allowed=False,
                 release_admitted=False, public_evidence_index_sha256=M.sha_file(public / 'SHA256SUMS'),
                 contract_bundle_sha256=M.sha_file(self.out / 'morph-current-custody.tar.gz'),
                 native_desktop={'bundle_sha256': M.sha_file(self.out / 'morph-desktop-linux-x86_64.tar.gz')})
        raw = json.dumps(q).encode()
        (self.out / 'gates/qualification/output.private.log').write_bytes(raw)
        path = self.out / 'gates/qualification/execution.json'
        receipt = M.load(path)
        receipt['log_sha256'] = M.V.digest(raw)
        path.write_text(json.dumps(receipt))
        (self.out / 'qualification.json').unlink()

    def finish(self):
        # Native execution/source capture are tested separately. These fixtures
        # exercise the actual assembler, exporter and bundle writer end to end.
        with patch.object(M.V, 'capture', return_value=self.candidate), \
             patch.object(M, 'node_identity', return_value=M.load(self.out / 'node-identity.json')), \
             patch.object(M, 'w1_results'):
            M.finish(self.out)

    def test_final_assembler_writes_public_bundle_after_all_receipts_and_artifacts_match(self):
        self.stage_finish()
        self.finish()
        self.assertTrue((self.out / 'morph-integration-evidence.tar.gz').is_file())
        self.assertTrue(M.load(self.out / 'integration-validation.json')['qualified_declared_plan'])
        self.assertTrue(M.load(self.out / 'integration-public/index.json')['full_w1_qualified'])

    def test_final_assembler_rejects_changed_packages_plan_qualification_and_failed_execution(self):
        self.stage_finish()
        snapshot = {p.relative_to(self.out): p.read_bytes() for p in self.out.rglob('*') if p.is_file()}
        for mutation in ['contract-package', 'desktop-package', 'plan', 'qualification', 'failed-gate', 'public-index']:
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.out)
                self.out.mkdir()
                for path, raw in snapshot.items():
                    dest = self.out / path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(raw)
                if mutation in ['contract-package', 'desktop-package']:
                    filename = 'morph-current-custody.tar.gz' if mutation == 'contract-package' else 'morph-desktop-linux-x86_64.tar.gz'
                    (self.out / filename).write_bytes(b'changed package')
                elif mutation == 'plan':
                    path = self.out / 'integration-plan.json'
                    plan = M.load(path)
                    plan['gates']['ci']['command'] = ['true']
                    path.write_text(json.dumps(plan))
                elif mutation == 'qualification':
                    path = self.out / 'gates/qualification/output.private.log'
                    q = M.load(path)
                    q['source_commit'] = 'f' * 40
                    path.write_text(json.dumps(q))
                    receipt = self.out / 'gates/qualification/execution.json'
                    value = M.load(receipt)
                    value['log_sha256'] = M.sha_file(path)
                    receipt.write_text(json.dumps(value))
                elif mutation == 'failed-gate':
                    path = self.out / 'gates/native/execution.json'
                    value = M.load(path)
                    value['exit_code'] = 7
                    path.write_text(json.dumps(value))
                else:
                    path = self.out / 'public-evidence/README.md'
                    path.write_text('changed export')
                    self.checksums(path.parent)
                with self.assertRaises(ValueError): self.finish()
                self.assertFalse((self.out / 'morph-integration-evidence.tar.gz').exists())

    def test_bundle_rejects_extra_even_indexed_private_file_link_and_changed_index(self):
        self.export()
        expected = self.qualification['public_evidence_index_sha256']
        directory = self.out / 'integration-public'
        (directory / 'private.json').write_text('{"key":"PRIVATE-MARKER"}')
        self.checksums(directory)
        with self.assertRaises(ValueError): M.bundle_public(self.out, expected)
        self.assertFalse((self.out / 'morph-integration-evidence.tar.gz').exists())
        (directory / 'private.json').unlink()
        self.checksums(directory)
        index = directory / 'node.json'
        original = index.read_bytes()
        index.unlink()
        outside = self.out / 'outside'
        outside.write_bytes(original)
        index.symlink_to(outside)
        with self.assertRaises(ValueError): M.bundle_public(self.out, expected)
        index.unlink()
        index.write_bytes(original)
        with self.assertRaises(ValueError): M.bundle_public(self.out, 'f' * 64)


if __name__ == '__main__': unittest.main()
