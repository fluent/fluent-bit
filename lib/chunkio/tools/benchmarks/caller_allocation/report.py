"""Print comparison tables from run.py's raw samples and allocation diagnostics."""
import argparse
import json
from pathlib import Path
from statistics import median

VARIANTS = ['previous', 'pr_fixed_hint', 'pr_append_hint']
CASES = [('sparse', 1, 'Sparse'), ('sparse_fragmented', 1, 'Sparse, separate records'),
         ('busy', 1, 'Busy'), ('mixed', 1, 'Mixed'), ('large', 1, 'Large first append'),
         ('reopen', 1, 'Reopen'), ('busy', 0, 'Busy, CRC off')]


def tables(root):
    raw = json.loads((root / 'raw.json').read_text())
    allocation = json.loads((root / 'allocations.json').read_text())
    manifest = json.loads((root / 'manifest.json').read_text())
    count = manifest['measured_runs']
    assert len(raw) == len(CASES) * len(VARIANTS) * (count + 1)
    assert len(allocation) == len(CASES) * len(VARIANTS)
    summary = {}
    for case, checksum, label in CASES:
        summary[label] = {}
        for variant in VARIANTS:
            rows = [r for r in raw if r['workload'] == case and r['checksum'] == checksum
                    and r['variant'] == variant and r['repeat'] > 0]
            assert len(rows) == count and all(r['correct'] for r in rows)
            diagnostic = next(r for r in allocation if r['workload'] == case
                              and r['checksum'] == checksum and r['variant'] == variant)
            summary[label][variant] = {
                'medians': {key: median(row[key] for row in rows)
                            for key, value in rows[0].items()
                            if isinstance(value, (int, float))},
                'cpu_range': [min(row['cpu_ms'] for row in rows), max(row['cpu_ms'] for row in rows)],
                'allocation': diagnostic,
            }
    main = ['| Workload / metric | Previous | PR fixed 256K hint | PR append-sized hint |',
            '| --- | ---: | ---: | ---: |']
    capacity = ['| Workload | Previous initial → final KiB/chunk | PR fixed hint initial → final | PR append-sized initial → final |',
                '| --- | ---: | ---: | ---: |']
    shape = ['| Workload | Logical MiB | Chunks | Appends | Records | Metadata bytes |',
             '| --- | ---: | ---: | ---: | ---: | ---: |']
    ranges = ['| Workload | Previous CPU ms range | PR fixed hint | PR append-sized |',
              '| --- | ---: | ---: | ---: |']
    for _, _, label in CASES:
        row = summary[label]
        for title, key, scale, precision in [('CPU ms', 'cpu_ms', 1, 2),
                                              ('allocated disk MiB', 'final_allocated_bytes', 1048576, 2),
                                              ('allocation amplification', 'amplification', 1, 3),
                                              ('remaps', 'remaps', 1, 0)]:
            values = [f'{row[v]["medians"][key] / scale:,.{precision}f}' for v in VARIANTS]
            main.append(f'| {label}: {title} | ' + ' | '.join(values) + ' |')
        values = []
        for variant in VARIANTS:
            metrics = row[variant]['medians']
            sizes = []
            for prefix in ['initial', 'final']:
                low, high = [metrics[f'{prefix}_capacity_{bound}'] / 1024 for bound in ['min', 'max']]
                sizes.append(f'{low:g}' if low == high else f'{low:g}–{high:g}')
            values.append(' → '.join(sizes))
        capacity.append(f'| {label} | ' + ' | '.join(values) + ' |')
        metrics = row['previous']['medians']
        shape.append(f'| {label} | {metrics["logical_bytes"]/1048576:g} | '
                     f'{metrics["chunk_count"]:,} | {metrics["appends"]:,} | '
                     f'{metrics["records"]:,} | {metrics["metadata_bytes"]:,} |')
        ranges.append(f'| {label} | ' + ' | '.join(
            f'{row[v]["cpu_range"][0]:.2f}–{row[v]["cpu_range"][1]:.2f}' for v in VARIANTS) + ' |')
    return summary, {'comparison': main, 'capacity': capacity, 'shape': shape, 'ranges': ranges}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    summary, sections = tables(args.directory)
    (args.directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    for name, lines in sections.items():
        content = '\n'.join(lines) + '\n'
        (args.directory / (name + '.md')).write_text(content)
        print(content)
