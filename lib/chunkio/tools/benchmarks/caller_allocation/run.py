"""Build one caller model against each library, then compare creation policies."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess

HARNESS = Path(__file__).resolve().parent
REPOSITORY = HARNESS.parents[2]
VARIANTS = {
    'previous': ('base', 'fixed'),
    'pr_fixed_hint': ('head', 'fixed'),
    'pr_append_hint': ('head', 'append'),
}
CASES = [('sparse', 1), ('sparse_fragmented', 1), ('busy', 1), ('mixed', 1), ('large', 1), ('reopen', 1), ('busy', 0)]


def build(source, library_build, output):
    command = ['cc', '-O3', '-Wall', '-Wextra', '-Werror',
               '-I' + str(REPOSITORY / 'tests'),
               '-isystem', str(source / 'include'), '-isystem', str(source / 'deps'),
               '-isystem', str(source / 'deps/monkey/include'),
               '-isystem', str(library_build / 'include'), str(HARNESS / 'bench.c'),
               str(library_build / 'src/libchunkio-static.a'),
               str(library_build / 'deps/crc32/libcio-crc32.a'),
               '-Wl,--wrap=cio_file_native_remap',
               '-Wl,--wrap=cio_file_native_resize', '-o', str(output)]
    subprocess.run(command, check=True)
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-source', type=Path, required=True)
    parser.add_argument('--base-build', type=Path, required=True)
    parser.add_argument('--head-source', type=Path, default=REPOSITORY)
    parser.add_argument('--head-build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu', default='2')
    parser.add_argument('--runs', type=int, default=9)
    args = parser.parse_args()
    assert args.runs > 0
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 8192), hard))
    builds = {}
    for variant in ['base', 'head']:
        source = getattr(args, variant + '_source').resolve()
        directory = getattr(args, variant + '_build').resolve()
        builds[variant] = build(source, directory, args.output / variant)
    manifest = {
        'kernel': platform.release(), 'machine': platform.machine(),
        'cpu_affinity': args.cpu, 'warmups': 1, 'measured_runs': args.runs,
        'baseline_commit': subprocess.check_output(['git', '-C', str(args.base_source),
                                                    'rev-parse', 'HEAD'], text=True).strip(),
        'pr_commit': subprocess.check_output(['git', '-C', str(args.head_source),
                                             'rev-parse', 'HEAD'], text=True).strip(),
        'build_commands': builds,
        'source_sha256': {str(path.relative_to(REPOSITORY)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in [HARNESS / 'bench.c', REPOSITORY / 'tests/cio_test_caller.h']},
        'variants': VARIANTS, 'cases': CASES,
        'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
        'filesystem': subprocess.check_output(['findmnt', '-T', os.environ.get('TMPDIR', '/tmp'),
                                               '-no', 'FSTYPE,SOURCE'], text=True).strip(),
        'page_size': os.sysconf('SC_PAGE_SIZE'),
        'library_sha256': {variant: hashlib.sha256(
            (getattr(args, variant + '_build') / 'src/libchunkio-static.a').read_bytes()).hexdigest()
            for variant in ['base', 'head']},
    }
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []
    diagnostics = []
    expected = {}

    def execute(case, checksum, variant, diagnostic):
        binary, policy = VARIANTS[variant]
        result = subprocess.run(['taskset', '-c', args.cpu, str(args.output / binary),
                                 case, policy, str(checksum), str(diagnostic)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"{case}/{variant}: {result.stderr}")
        sample = json.loads(result.stdout)
        assert sample['correct']
        shape = tuple(sample[key] for key in ['logical_bytes', 'records', 'appends', 'chunk_count'])
        previous_shape = expected.setdefault((case, checksum), shape)
        assert shape == previous_shape, 'Caller lifecycle differs across allocation policies'
        sample.update(workload=case, checksum=checksum, variant=variant)
        return sample

    for repeat in range(args.runs + 1):
        for index, (case, checksum) in enumerate(CASES):
            order = list(VARIANTS)
            rotation = (repeat + index) % len(order)
            order = order[rotation:] + order[:rotation]
            for variant in order:
                sample = execute(case, checksum, variant, 0)
                sample['repeat'] = repeat
                rows.append(sample)
                print(json.dumps(sample), flush=True)
                (args.output / 'raw.json').write_text(json.dumps(rows, indent=2) + '\n')

    # Extra stat calls occur only in this untimed allocation diagnostic pass.
    for case, checksum in CASES:
        for variant in VARIANTS:
            sample = execute(case, checksum, variant, 1)
            chunks = sample.pop('chunks')
            groups = Counter((('cold' if chunk['key'] < 1000 else 'hot')
                              if case == 'mixed' else 'all',
                              chunk['initial'], chunk['final'], chunk['allocated'],
                              chunk['logical'], chunk['appends']) for chunk in chunks)
            sample['capacity_histogram'] = [dict(group=key[0], initial=key[1], final=key[2],
                                                  allocated=key[3], logical=key[4], appends=key[5],
                                                  chunks=count) for key, count in sorted(groups.items())]
            diagnostics.append(sample)
            (args.output / 'allocations.json').write_text(json.dumps(diagnostics, indent=2) + '\n')
    with (args.output / 'results.csv').open('w') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
