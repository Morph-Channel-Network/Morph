#!/usr/bin/env python3
"""Bounded W1 campaigns over existing runners; raw evidence stays private."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(command, log, env=None):
    with log.open('xb') as stream:
        subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                       stderr=subprocess.STDOUT, check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('campaign', choices=['fuzz', 'shadow'])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--node', type=Path)
    p.add_argument('--fiber-source', type=Path)
    a = p.parse_args()
    os.umask(0o077)
    a.output.mkdir(mode=0o700)
    if a.campaign == 'fuzz':
        for seed in (1, 17, 332043276360):
            run(['cargo', 'run', '--locked', '-p', 'morph-xtask', '--bin', 'morph-fuzz', '--',
                 '--output', str(a.output / str(seed)), '--seed', str(seed),
                 '--cases', '10000', '--seconds', '180'], a.output / f'{seed}.private.log')
    else:
        if a.node is None or a.fiber_source is None:
            p.error('shadow requires --node and --fiber-source')
        env = dict(os.environ, CKB_BIN=str(a.node), FIBER_SOURCE=str(a.fiber_source))
        hook_log = a.output / 'hook.private.log'
        run(['bash', 'scripts/fiber-shadow-hook-check.sh'], hook_log, env)
        prefix = 'Fiber shadow module checks passed. Evidence: '
        rows = [line[len(prefix):] for line in hook_log.read_text().splitlines() if line.startswith(prefix)]
        if len(rows) != 1:
            raise ValueError('missing unique hook evidence')
        evidence = Path(rows[0]).resolve(strict=True)
        if not evidence.is_relative_to(ROOT / 'target/fiber-shadow-evidence'):
            raise ValueError('hook evidence escaped owned target')
        verification = json.loads((evidence / 'verification.json').read_text())
        if verification['passed'] is not True:
            raise ValueError('hook tests failed')
        env.update(FIBER_CHECKOUT=verification['checkout'], OUT_DIR=str(a.output / 'native'))
        run(['bash', 'scripts/devnet-shadow-service-e2e.sh'], a.output / 'native.private.log', env)
        # Fixed paths/hashes are checked again by the integration exporter.
        (a.output / 'hook.json').write_text(json.dumps(verification, indent=2) + '\n')


if __name__ == '__main__':
    main()
