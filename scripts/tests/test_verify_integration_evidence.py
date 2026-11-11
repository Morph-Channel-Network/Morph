import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-integration-evidence.py'
spec = importlib.util.spec_from_file_location('integration_evidence', SCRIPT)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class IntegrationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.bindings = {'cargo-lock': 'Cargo.lock', 'rust-toolchain': 'rust-toolchain.toml',
                         'deployment-manifest': 'contracts.json', 'runtime': 'crates/runtime/schema.sql'}
        for path, content in [('Cargo.lock', 'lock'), ('rust-toolchain.toml', 'toolchain'),
                              ('crates/runtime/schema.sql', 'schema1')]:
            dest = self.repo / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
        scripts = []
        for index, name in enumerate(sorted(evidence.SCRIPTS)):
            raw = bytes([index]) * 64  # Synthetic files: no VM execution claimed.
            (self.repo / name).write_bytes(raw)
            self.bindings['elf-' + name] = name
            scripts.append({'name': name, 'size_bytes': len(raw),
                            'ckb_data_hash': '0x' + hashlib.blake2b(raw, digest_size=32,
                                                                  person=b'ckb-default-hash').hexdigest()})
        (self.repo / 'contracts.json').write_text(json.dumps({'schema': 'morph.contract_release_manifest',
                                                            'scripts': scripts}))
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic candidate')
        self.plan = {'schema': 'morph.integration_evidence_plan.v1', 'scope': evidence.SCOPE,
                     'bindings': self.bindings, 'schemas': {'runtime': 'morph.runtime.v1'},
                     'gates': {'restart': {'required': True, 'command': ['make', 'test'],
                                          'configuration': ['runtime'], 'faults': ['process-kill'],
                                          'replay': ['restart'], 'exclusion': ''},
                               'independent': {'required': False, 'command': ['external-attestation'],
                                               'configuration': [], 'faults': [], 'replay': [],
                                               'exclusion': 'Owner excluded independent review from local no-value scope.'}}}
        self.candidate = evidence.capture(self.plan, self.repo)
        self.candidate['captured_at'] = 100
        report = {'replays': [{'scenario': 'synthetic-restart'}]}
        raw = json.dumps(report).encode()
        (self.reports / 'restart.json').write_bytes(raw)
        candidate_hash = evidence.digest(evidence.canonical(self.candidate))
        self.manifest = {'schema': 'morph.integration_evidence.v1', 'scope': evidence.SCOPE,
                         'candidate_sha256': candidate_hash, 'started_at': 101, 'finished_at': 110,
                         'gates': {}}
        for name, plan in self.plan['gates'].items():
            required = plan['required']
            self.manifest['gates'][name] = {
                'status': 'pass' if required else 'deferred', 'candidate_sha256': candidate_hash,
                'command_sha256': evidence.digest(evidence.canonical(plan['command'])),
                'configuration': {k: self.candidate['bindings'][k] for k in plan['configuration']},
                'faults': plan['faults'] if required else [], 'started_at': 102, 'finished_at': 109,
                'exit_code': 0 if required else None,
                'reports': {'restart.json': evidence.digest(raw)} if required else {},
                'execution': 'execution.json' if required else None,
                'replay': {'restart': {'report': 'restart.json', 'pointer': '/replays/0'}} if required else {},
                'reason': '' if required else plan['exclusion']}


        row = self.manifest['gates']['restart']
        receipt = {key: row[key] for key in ('candidate_sha256', 'command_sha256', 'configuration',
                                             'started_at', 'finished_at', 'exit_code')}
        receipt.update(schema='morph.integration_execution.v1', gate='restart', source_unchanged=True,
                       timed_out=False, log_sha256=evidence.digest(b''))
        raw = json.dumps(receipt).encode()
        (self.reports / 'execution.json').write_bytes(raw)
        row['reports']['execution.json'] = evidence.digest(raw)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, stderr=subprocess.DEVNULL).decode().strip()

    def validate(self, manifest=None, candidate=None, current=None, plan=None):
        return evidence.validate(plan or self.plan, candidate or self.candidate,
                                 manifest or self.manifest, self.reports,
                                 current or evidence.capture(self.plan, self.repo), now=120)

    def test_current_plan_accepts_explicit_exclusion_without_fabricating_attestation(self):
        result = self.validate()
        self.assertTrue(result['qualified_declared_plan'])
        self.assertFalse(result['independent_attestation'])
        self.assertFalse(result['deployment_authorized'])
        self.assertEqual(result['gate_status']['independent'], 'deferred')
        exported = json.dumps(result)
        self.assertNotIn('synthetic-restart', exported)
        self.assertNotIn('make', exported)
        self.assertNotIn('restart.json', exported)

    def test_missing_failed_skipped_and_falsely_passed_gates_reject(self):
        for mutation in ['missing', 'extra', 'failed', 'skipped', 'exit', 'bool-exit', 'reason', 'missing-reports']:
            with self.subTest(mutation=mutation):
                manifest = copy.deepcopy(self.manifest)
                row = manifest['gates']['restart']
                if mutation == 'missing': del manifest['gates']['restart']
                elif mutation == 'extra': manifest['gates']['extra'] = copy.deepcopy(row)
                elif mutation == 'failed': row.update(status='fail', exit_code=1, reason='failed', faults=[], replay={})
                elif mutation == 'skipped': row.update(status='skip', exit_code=None, reason='skipped', faults=[], replay={})
                elif mutation == 'exit': row['exit_code'] = 1
                elif mutation == 'bool-exit': row['exit_code'] = False
                elif mutation == 'reason': row['reason'] = 'unsupported'
                else: row['reports'] = {}
                with self.assertRaises(ValueError): self.validate(manifest=manifest)

    def test_binding_schema_source_dirty_and_committed_source_changes_reject(self):
        for field, value in [('source_commit', 'f' * 40), ('source_tree_sha256', 'f' * 64),
                             ('dirty', True), ('schemas', {'runtime': 'morph.runtime.v2'}),
                             ('bindings', {})]:
            with self.subTest(field=field):
                current = copy.deepcopy(self.candidate)
                current[field] = value
                with self.assertRaises(ValueError): self.validate(current=current)
        (self.repo / 'Cargo.lock').write_text('changed')
        with self.assertRaises(ValueError): self.validate()
        self.git('add', 'Cargo.lock')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Changed candidate')
        with self.assertRaises(ValueError): self.validate()

    def test_changed_elf_or_declared_deployment_rejects_capture(self):
        name = sorted(evidence.SCRIPTS)[0]
        path = self.repo / name
        original = path.read_bytes()
        path.write_bytes(original + b'changed')
        with self.assertRaises(ValueError): evidence.capture(self.plan, self.repo)
        path.write_bytes(original)
        deployment = self.repo / 'contracts.json'
        value = json.loads(deployment.read_text())
        value['scripts'][0]['ckb_data_hash'] = '0x' + 'f' * 64
        deployment.write_text(json.dumps(value))
        with self.assertRaises(ValueError): evidence.capture(self.plan, self.repo)

    def test_gate_command_config_identity_faults_and_replay_reject_substitution(self):
        mutations = [('candidate_sha256', 'f' * 64), ('command_sha256', 'f' * 64),
                     ('configuration', {}), ('faults', []), ('replay', {}),
                     ('started_at', 99), ('finished_at', 111)]
        for key, value in mutations:
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.manifest)
                manifest['gates']['restart'][key] = value
                with self.assertRaises(ValueError): self.validate(manifest=manifest)
        for pointer in ['/missing', '/replays/01', '/replays/2', '/replays/~2']:
            manifest = copy.deepcopy(self.manifest)
            manifest['gates']['restart']['replay']['restart']['pointer'] = pointer
            with self.assertRaises(ValueError): self.validate(manifest=manifest)

    def test_stale_future_scope_and_changed_plan_reject(self):
        for field, value in [('started_at', 99), ('finished_at', 121), ('scope', 'mainnet'),
                             ('schema', 'morph.integration_evidence.v0')]:
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.assertRaises(ValueError): self.validate(manifest=manifest)
        plan = copy.deepcopy(self.plan)
        plan['gates']['restart']['required'] = False
        plan['gates']['restart']['exclusion'] = 'Removed gate'
        with self.assertRaises(ValueError): self.validate(plan=plan)

    def test_changed_missing_linked_oversized_report_and_traversal_reject(self):
        report = self.reports / 'restart.json'
        original = report.read_bytes()
        report.write_bytes(original + b' ')
        with self.assertRaises(ValueError): self.validate()
        report.unlink()
        with self.assertRaises(ValueError): self.validate()
        outside = self.root / 'outside.json'
        outside.write_bytes(original)
        report.symlink_to(outside)
        with self.assertRaises(ValueError): self.validate()
        report.unlink()
        report.write_bytes(b'x' * (evidence.MAX_FILE + 1))
        with self.assertRaises(ValueError): self.validate()
        report.write_bytes(original)
        for path in ['../outside.json', '/outside.json', './restart.json', 'a/../restart.json']:
            manifest = copy.deepcopy(self.manifest)
            manifest['gates']['restart']['reports'] = {path: evidence.digest(original)}
            with self.assertRaises(ValueError): self.validate(manifest=manifest)


    def test_execution_receipt_failure_cannot_be_promoted_to_pass_even_after_rehash(self):
        path = self.reports / 'execution.json'
        receipt = json.loads(path.read_bytes())
        for field, value in [('exit_code', 1), ('timed_out', True), ('source_unchanged', False),
                             ('gate', 'different'), ('started_at', 101)]:
            with self.subTest(field=field):
                altered = copy.deepcopy(receipt)
                altered[field] = value
                raw = json.dumps(altered).encode()
                path.write_bytes(raw)
                manifest = copy.deepcopy(self.manifest)
                manifest['gates']['restart']['reports']['execution.json'] = evidence.digest(raw)
                with self.assertRaises(ValueError): self.validate(manifest=manifest)

    def test_real_runner_keeps_raw_output_private_and_records_actual_failure_and_change(self):
        cases = [('success', "print('synthetic-sensitive-log')", True),
                 ('failure', 'raise SystemExit(7)', False),
                 ('change', "from pathlib import Path; Path('Cargo.lock').write_text('changed')", False),
                 ('timeout', 'import time; time.sleep(30)', False)]
        for name, code, success in cases:
            with self.subTest(name=name):
                (self.repo / 'Cargo.lock').write_text('lock')
                plan = copy.deepcopy(self.plan)
                plan['gates']['restart']['command'] = [sys.executable, '-c', code]
                candidate = evidence.capture(plan, self.repo)
                output = self.root / ('run-' + name)
                if success:
                    evidence.run_gate(plan, candidate, 'restart', self.repo, output, 1)
                else:
                    with self.assertRaises(ValueError):
                        evidence.run_gate(plan, candidate, 'restart', self.repo, output, 1)
                receipt = json.loads((output / 'execution.json').read_text())
                self.assertNotIn('synthetic-sensitive-log', json.dumps(receipt))
                self.assertEqual(os.stat(output / 'output.private.log').st_mode & 0o777, 0o600)
                self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
                self.assertEqual(receipt['timed_out'], name == 'timeout')
                self.assertEqual(receipt['source_unchanged'], name != 'change')
                self.assertEqual(receipt['exit_code'], {'success': 0, 'failure': 7, 'change': 0, 'timeout': 124}[name])
                with self.assertRaises((ValueError, FileExistsError)):
                    evidence.run_gate(plan, candidate, 'restart', self.repo, output, 1)

    def test_cli_capture_run_validate_and_dirty_capture_rejection(self):
        plan = copy.deepcopy(self.plan)
        plan['gates']['restart']['command'] = [sys.executable, '-c', 'print("synthetic CLI run")']
        plan['gates']['restart']['faults'] = ['synthetic-run']
        plan_path = self.root / 'plan.json'
        plan_path.write_text(json.dumps(plan))
        candidate_path = self.root / 'candidate.json'
        prefix = [sys.executable, '-B', str(SCRIPT), '--root', str(self.repo), '--plan', str(plan_path)]
        subprocess.run(prefix + ['capture', '--output', str(candidate_path)], check=True, capture_output=True)
        output = self.root / 'cli-run'
        subprocess.run(prefix + ['run', '--candidate', str(candidate_path), '--gate', 'restart',
                                 '--output', str(output), '--timeout', '5'], check=True, capture_output=True)
        candidate = json.loads(candidate_path.read_text())
        raw = (output / 'execution.json').read_bytes()
        receipt = json.loads(raw)
        (self.reports / 'execution.json').write_bytes(raw)
        manifest = copy.deepcopy(self.manifest)
        manifest.update(candidate_sha256=evidence.digest(evidence.canonical(candidate)),
                        started_at=receipt['started_at'], finished_at=receipt['finished_at'])
        for row in manifest['gates'].values():
            row.update(candidate_sha256=manifest['candidate_sha256'],
                       started_at=manifest['started_at'], finished_at=manifest['finished_at'])
        row = manifest['gates']['restart']
        row.update(command_sha256=receipt['command_sha256'], faults=['synthetic-run'])
        row['reports']['execution.json'] = evidence.digest(raw)
        index = self.root / 'index.json'
        index.write_text(json.dumps(manifest))
        result = subprocess.run(prefix + ['validate', '--candidate', str(candidate_path),
                                         '--manifest', str(index), '--reports', str(self.reports)],
                                check=True, capture_output=True)
        self.assertTrue(json.loads(result.stdout)['qualified_declared_plan'])
        (self.repo / 'Cargo.lock').write_text('dirty')
        failed_output = self.root / 'dirty-candidate.json'
        failure = subprocess.run(prefix + ['capture', '--output', str(failed_output)], capture_output=True)
        self.assertNotEqual(failure.returncode, 0)
        self.assertFalse(failed_output.exists())

    def test_strict_json_and_missing_schema_binding(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}']:
            with self.assertRaises(ValueError): evidence.decode(raw)
        plan = copy.deepcopy(self.plan)
        plan['schemas']['unbound'] = 'morph.missing.v1'
        with self.assertRaises(ValueError): evidence.plan_validate(plan)
        manifest = copy.deepcopy(self.manifest)
        manifest['unknown'] = True
        with self.assertRaises(ValueError): self.validate(manifest=manifest)


if __name__ == '__main__':
    unittest.main()
