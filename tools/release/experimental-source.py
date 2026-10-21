"""Validate the source cohort before experimental publication; no network writes."""
import argparse
import json
import re
from pathlib import Path

ARTIFACTS = {
    'experimental-darwin-arm64', 'experimental-darwin-x64',
    'experimental-linux-arm64-gnu', 'experimental-linux-arm64-musl',
    'experimental-linux-x64-gnu', 'experimental-linux-x64-gnu-glibc2_28',
    'experimental-linux-x64-musl', 'experimental-windows-x64',
}

def validate(run, artifacts, repository, run_id, workflow_path):
    # This validator runs from the default branch before checking out a source
    # cohort. Preserve historical publication except explicitly withheld sources.
    holds_path = Path(__file__).resolve().parents[2]/'.github/experimental-release-holds.json'
    if holds_path.exists():
        holds = json.loads(holds_path.read_text())
        if (set(holds) != {'version', 'sources'} or holds['version'] != 1
            or not isinstance(holds['sources'], dict)
            or any(not re.fullmatch(r'[0-9a-f]{40}', k) or not isinstance(v, str) or not v
                   for k, v in holds['sources'].items())):
            raise ValueError('invalid experimental publication hold registry')
        if run.get('head_sha') in holds['sources']:
            raise ValueError('source is explicitly withheld from experimental publication')

    if (workflow_path != '.github/workflows/distribution-spike.yml'
        or run.get('id') != run_id
        or run.get('event') not in {'push', 'workflow_dispatch'}
        or run.get('head_branch') != 'main'
        or run.get('head_repository', {}).get('full_name') != repository
        or run.get('status') != 'completed'
        or run.get('conclusion') != 'success'
        or not re.fullmatch(r'[0-9a-f]{40}', run.get('head_sha', ''))):
        raise ValueError('source must be a successful exact main-branch native candidate')
    rows = artifacts.get('artifacts', [])
    if (artifacts.get('total_count') != len(ARTIFACTS)
        or len(rows) != len(ARTIFACTS)
        or {a.get('name') for a in rows} != ARTIFACTS
        or any(a.get('expired') is not False for a in rows)):
        raise ValueError('source requires all eight unique unexpired native artifacts')
    return {'source_sha': run['head_sha'], 'source_run_id': run_id}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--repository', required=True)
    p.add_argument('--run-id', type=int, required=True)
    p.add_argument('--workflow-path', required=True)
    p.add_argument('--github-output', type=Path, required=True)
    a = p.parse_args()
    result = validate(json.loads(a.run.read_text()), json.loads(a.artifacts.read_text()),
                      a.repository, a.run_id, a.workflow_path)
    with a.github_output.open('a') as f:
        for k, v in result.items():
            f.write(f'{k}={v}\n')

if __name__ == '__main__':
    main()
