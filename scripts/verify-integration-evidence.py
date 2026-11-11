#!/usr/bin/env python3
"""Validate a current integration evidence index against an independent plan.

Read-only: no execution, publication, signing or private-artifact copying. A
successful result is local, controlled-devnet/no-real-assets qualification of
this declared plan, never an independent attestation or deployment approval.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import signal
import re
import subprocess
import time
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 16 * 1024 * 1024
SCOPE = 'controlled-devnet-no-real-assets'
SCRIPTS = {'morph-state-lock', 'morph-state-type', 'morph-vault-lock',
           'morph-factory-type', 'morph-factory-vault-lock', 'morph-batch-lock',
           'morph-sponsor-lock', 'morph-devnet-xudt'}
BASE_BINDINGS = {'cargo-lock', 'rust-toolchain', 'deployment-manifest'} | {'elf-' + s for s in SCRIPTS}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()), 'unexpected or missing fields')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[a-z][a-z0-9.-]{0,95}', value), 'invalid identifier')


def checksum(value):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid checksum')


def number(value):
    require(type(value) is int and 0 <= value <= 2**53 - 1, 'invalid bounded integer')


def relative(value):
    require(type(value) is str and 0 < len(value) <= 512, 'invalid path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and '..' not in path.parts
            and '\\' not in value and '\x00' not in value and value != '.', 'unsafe path')
    return path


def read(root, name):
    relative(name)
    root = root.absolute()
    require(root == root.resolve(), 'linked evidence root')
    path = root
    for part in PurePosixPath(name).parts:
        path /= part
        require(not path.is_symlink(), 'linked evidence path')
    require(path.resolve().is_relative_to(root.resolve()) and path.is_file(), 'missing evidence file')
    with path.open('rb') as handle:
        raw = handle.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, 'oversized evidence file')
    return raw


def decode(raw):
    require(len(raw) <= MAX_FILE, 'oversized JSON')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def strings(values):
    require(type(values) is list and len(values) <= 128, 'invalid identifier list')
    for value in values:
        identifier(value)
    require(len(values) == len(set(values)), 'duplicate identifier')


def plan_validate(plan):
    exact(plan, 'schema scope bindings schemas gates')
    require(plan['schema'] == 'morph.integration_evidence_plan.v1' and plan['scope'] == SCOPE,
            'unsupported plan or scope')
    require(type(plan['bindings']) is dict and BASE_BINDINGS <= set(plan['bindings'])
            and len(plan['bindings']) <= 128, 'incomplete identity bindings')
    for role, path in plan['bindings'].items():
        identifier(role)
        relative(path)
    require(plan['bindings']['cargo-lock'] == 'Cargo.lock'
            and plan['bindings']['rust-toolchain'] == 'rust-toolchain.toml', 'wrong source binding')
    require(type(plan['schemas']) is dict and 0 < len(plan['schemas']) <= 64, 'missing schemas')
    for role, schema in plan['schemas'].items():
        identifier(role)
        require(type(schema) is str and re.fullmatch(r'[a-z][a-z0-9._-]{0,127}', schema), 'invalid schema label')
        require(role in plan['bindings'], 'schema has no implementation/artifact binding')
    require(type(plan['gates']) is dict and 0 < len(plan['gates']) <= 64, 'missing gates')
    require(any(gate.get('required') is True for gate in plan['gates'].values()
                if type(gate) is dict), 'no required gate')
    for name, gate in plan['gates'].items():
        identifier(name)
        exact(gate, 'required command configuration faults replay exclusion')
        require(type(gate['required']) is bool, 'invalid required flag')
        require(type(gate['command']) is list and 0 < len(gate['command']) <= 64
                and all(type(arg) is str and 0 < len(arg) <= 1024 and '\x00' not in arg
                        for arg in gate['command']), 'invalid command')
        for field in ('configuration', 'faults', 'replay'):
            strings(gate[field])
        require(set(gate['configuration']) <= set(plan['bindings']), 'unbound gate configuration')
        require(type(gate['exclusion']) is str and len(gate['exclusion']) <= 2048, 'invalid scope rationale')
        require((gate['exclusion'] == '') if gate['required'] else bool(gate['exclusion'].strip()),
                'required gate excluded or optional gate unexplained')


def capture(plan, root=ROOT):
    plan_validate(plan)
    root = root.resolve()
    # Share the existing source inventory, including untracked implementation.
    spec = importlib.util.spec_from_file_location('current_evidence_ledger', ROOT / 'scripts/current-stateful-ledger.py')
    ledger = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ledger)
    ledger.ROOT = root
    commit = ledger.git('rev-parse', 'HEAD')
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'invalid source commit')
    dirty = bool(ledger.git('status', '--porcelain', '--untracked-files=no') or
                 ledger.git('ls-files', '--others', '--exclude-standard', '--', *ledger.IMPLEMENTATION_PATHS))
    source_digest = ledger.source_digest()
    bindings = {role: digest(read(root, path)) for role, path in plan['bindings'].items()}
    deployment = decode(read(root, plan['bindings']['deployment-manifest']))
    require(deployment.get('schema') == 'morph.contract_release_manifest', 'unsupported deployment manifest')
    scripts = deployment.get('scripts')
    require(type(scripts) is list and len(scripts) == 8 and
            {row.get('name') for row in scripts} == SCRIPTS, 'incomplete deployment manifest')
    for row in scripts:
        raw = read(root, plan['bindings']['elf-' + row['name']])
        ckb_hash = '0x' + hashlib.blake2b(raw, digest_size=32, person=b'ckb-default-hash').hexdigest()
        require(row.get('ckb_data_hash') == ckb_hash and row.get('size_bytes') == len(raw),
                'deployment/ELF mismatch')
    dirty_after = bool(ledger.git('status', '--porcelain', '--untracked-files=no') or
                       ledger.git('ls-files', '--others', '--exclude-standard', '--', *ledger.IMPLEMENTATION_PATHS))
    require(ledger.git('rev-parse', 'HEAD') == commit and dirty_after == dirty
            and ledger.source_digest() == source_digest, 'candidate changed during capture')
    return {'schema': 'morph.integration_candidate.v1', 'scope': SCOPE,
            'source_commit': commit, 'source_tree_sha256': source_digest,
            'dirty': dirty, 'captured_at': int(time.time()), 'plan_sha256': digest(canonical(plan)),
            'bindings': bindings, 'schemas': plan['schemas']}


def validate(plan, expected, manifest, reports_root, current, now=None):
    plan_validate(plan)
    exact(expected, 'schema scope source_commit source_tree_sha256 dirty captured_at plan_sha256 bindings schemas')
    require(expected['schema'] == 'morph.integration_candidate.v1' and expected['scope'] == SCOPE,
            'unsupported candidate')
    number(expected['captured_at'])
    require(expected['dirty'] is False and
            {k: v for k, v in current.items() if k != 'captured_at'} ==
            {k: v for k, v in expected.items() if k != 'captured_at'}, 'dirty or changed candidate')
    require(expected['plan_sha256'] == digest(canonical(plan)), 'candidate plan changed')
    exact(manifest, 'schema scope candidate_sha256 started_at finished_at gates')
    require(manifest['schema'] == 'morph.integration_evidence.v1' and manifest['scope'] == SCOPE,
            'unsupported manifest or expanded scope')
    candidate_hash = digest(canonical(expected))
    require(manifest['candidate_sha256'] == candidate_hash, 'manifest candidate mismatch')
    now = int(time.time()) if now is None else now
    for field in ('started_at', 'finished_at'):
        number(manifest[field])
    require(expected['captured_at'] <= manifest['started_at'] <= manifest['finished_at'] <= now,
            'stale evidence or invalid campaign time range')
    require(type(manifest['gates']) is dict and set(manifest['gates']) == set(plan['gates']),
            'missing or undeclared gate')
    checked = {}
    total_bytes = 0
    report_bytes = {}
    for name, required in plan['gates'].items():
        row = manifest['gates'][name]
        exact(row, 'status candidate_sha256 command_sha256 configuration faults replay started_at finished_at exit_code reports execution reason')
        require(row['candidate_sha256'] == candidate_hash, 'stale gate candidate')
        require(row['command_sha256'] == digest(canonical(required['command'])), 'gate command differs')
        require(row['configuration'] == {key: expected['bindings'][key] for key in required['configuration']},
                'gate configuration differs')
        strings(row['faults'])
        require(set(row['faults']) == (set(required['faults']) if row['status'] == 'pass' else set()),
                'fault family coverage differs')
        for field in ('started_at', 'finished_at'):
            number(row[field])
        require(manifest['started_at'] <= row['started_at'] <= row['finished_at'] <= manifest['finished_at'],
                'gate outside campaign time range')
        require(row['status'] in ('pass', 'fail', 'skip', 'unsupported', 'deferred'), 'invalid gate status')
        require(type(row['reason']) is str and len(row['reason']) <= 2048, 'invalid gate reason')
        passed = row['status'] == 'pass'
        require(not required['required'] or passed, 'required gate did not pass')
        require((type(row['exit_code']) is int and row['exit_code'] == 0 and row['reason'] == '') if passed
                else (bool(row['reason'].strip()) and (row['exit_code'] is None or
                      (type(row['exit_code']) is int and 1 <= row['exit_code'] <= 255))),
                'status/exit/reason contradiction')
        require(type(row['reports']) is dict and len(row['reports']) <= 64 and
                (bool(row['reports']) or not passed), 'missing result artifacts')
        for path, sha in row['reports'].items():
            checksum(sha)
            if path not in report_bytes:
                raw = read(reports_root, path)
                total_bytes += len(raw)
                require(total_bytes <= 64 * 1024 * 1024, 'aggregate report budget exceeded')
                report_bytes[path] = raw
            raw = report_bytes[path]
            require(digest(raw) == sha, 'changed result artifact')
            checked[path] = sha
        if row['status'] in ('pass', 'fail'):
            require(row['execution'] in row['reports'], 'missing execution receipt')
            receipt = decode(report_bytes[row['execution']])
            exact(receipt, 'schema gate candidate_sha256 command_sha256 configuration started_at finished_at exit_code source_unchanged timed_out log_sha256')
            require(receipt['schema'] == 'morph.integration_execution.v1' and receipt['gate'] == name,
                    'wrong execution receipt')
            for field in ('candidate_sha256', 'command_sha256', 'configuration', 'started_at', 'finished_at', 'exit_code'):
                require(receipt[field] == row[field] and type(receipt[field]) is type(row[field]),
                        'execution/manifest contradiction')
            require(type(receipt['source_unchanged']) is bool and type(receipt['timed_out']) is bool,
                    'invalid execution outcome')
            checksum(receipt['log_sha256'])
            require(not passed or (receipt['source_unchanged'] and not receipt['timed_out']),
                    'failed execution reported as pass')
        else:
            require(row['execution'] is None, 'unexecuted gate has execution receipt')
        require(type(row['replay']) is dict, 'invalid replay references')
        require(set(row['replay']) == (set(required['replay']) if passed else set()), 'missing replay family')
        for family, reference in row['replay'].items():
            exact(reference, 'report pointer')
            require(reference['report'] in row['reports'], 'unindexed replay report')
            pointer = reference['pointer']
            require(type(pointer) is str and pointer.startswith('/') and len(pointer) <= 1024,
                    'invalid replay JSON pointer')
            value = decode(report_bytes[reference['report']])
            for component in pointer[1:].split('/'):
                require(re.search(r'~(?![01])', component) is None, 'invalid JSON pointer escape')
                component = component.replace('~1', '/').replace('~0', '~')
                if type(value) is list:
                    require(re.fullmatch(r'0|[1-9][0-9]*', component), 'noncanonical replay index')
                    require(int(component) < len(value), 'missing replay index')
                    value = value[int(component)]
                else:
                    require(type(value) is dict and component in value, 'missing replay location')
                    value = value[component]
            require(value is not None and value is not False and value != '' and value != [] and value != {},
                    'empty replay evidence')
    # Deliberately export only hashes and finite states; never raw logs, arguments,
    # private snapshots, keys, preimages or unreviewed arbitrary report content.
    return {'schema': 'morph.integration_validation.v1', 'scope': SCOPE,
            'candidate_sha256': candidate_hash, 'manifest_sha256': digest(canonical(manifest)),
            'plan_sha256': digest(canonical(plan)), 'gate_status': {k: v['status'] for k, v in manifest['gates'].items()},
            'artifact_count': len(checked), 'qualified_declared_plan': True,
            'independent_attestation': False, 'deployment_authorized': False}



def same_candidate(left, right):
    return {k: v for k, v in left.items() if k != 'captured_at'} == {k: v for k, v in right.items() if k != 'captured_at'}


def run_gate(plan, candidate, name, root, output, timeout):
    """Execute a trusted plan argv without a shell. Raw logs remain private."""
    require(1 <= timeout <= 86400, 'invalid execution timeout')
    require(name in plan['gates'], 'undeclared gate')
    before = capture(plan, root)
    require(candidate['dirty'] is False and same_candidate(before, candidate), 'dirty or changed candidate')
    require(candidate['plan_sha256'] == digest(canonical(plan)), 'changed plan')
    gate = plan['gates'][name]
    # Fresh directory only; do not overwrite an earlier run or follow a link.
    output.mkdir(mode=0o700)
    log_path = output / 'output.private.log'
    started = int(time.time())
    timed_out = False
    with log_path.open('xb') as log:
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(gate['command'], cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            result = 124
    finished = int(time.time())
    try:
        unchanged = same_candidate(capture(plan, root), candidate)
    except (ValueError, OSError, subprocess.CalledProcessError):
        unchanged = False
    # Streaming hashes: raw logs need not fit the public JSON artifact budget.
    def file_hash(path):
        with path.open('rb') as handle:
            return hashlib.file_digest(handle, 'sha256').hexdigest()
    receipt = {'schema': 'morph.integration_execution.v1', 'gate': name,
               'candidate_sha256': digest(canonical(candidate)),
               'command_sha256': digest(canonical(gate['command'])),
               'configuration': {key: candidate['bindings'][key] for key in gate['configuration']},
               'started_at': started, 'finished_at': finished,
               'exit_code': result if result >= 0 else min(255, 128 - result),
               'source_unchanged': unchanged, 'timed_out': timed_out,
               'log_sha256': file_hash(log_path)}
    with (output / 'execution.json').open('x', encoding='utf8') as handle:
        json.dump(receipt, handle, indent=2)
        handle.write('\n')
    require(result == 0 and unchanged and not timed_out, 'gate failed; execution receipt retained')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=ROOT)
    actions = parser.add_subparsers(dest='action', required=True)
    cap = actions.add_parser('capture')
    cap.add_argument('--output', type=Path, required=True)
    run = actions.add_parser('run')
    run.add_argument('--candidate', type=Path, required=True)
    run.add_argument('--gate', required=True)
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--timeout', type=int, default=3600)
    val = actions.add_parser('validate')
    val.add_argument('--candidate', type=Path, required=True)
    val.add_argument('--manifest', type=Path, required=True)
    val.add_argument('--reports', type=Path, required=True)
    args = parser.parse_args()
    load = lambda path: decode(read(path.parent, path.name))
    plan = load(args.plan)
    current = capture(plan, args.root)
    if args.action == 'capture':
        require(not current['dirty'], 'commit source before candidate capture')
        with args.output.open('x', encoding='utf8') as output:
            json.dump(current, output, indent=2)
            output.write('\n')
    elif args.action == 'run':
        run_gate(plan, load(args.candidate), args.gate, args.root, args.output, args.timeout)
    else:
        result = validate(plan, load(args.candidate), load(args.manifest), args.reports, current)
        require(same_candidate(capture(plan, args.root), current), 'candidate changed during validation')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'integration evidence rejected: {error}') from error
