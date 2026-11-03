"""Run one warmup and five measurements, alternating the version order."""
import json
from run import run, ROOT

results = []
for repeat in range(6):
    for index, case in enumerate(['steady_fs', 'steady_crc', 'many_tags',
                                  'backpressure', 'memory']):
        variants = ['base', 'head'] if (repeat + index) % 2 == 0 else ['head', 'base']
        for variant in variants:
            label = 'warmup' if repeat == 0 else f'measured-{repeat}'
            results.append(run(case, variant, label))
            (ROOT / 'raw.json').write_text(json.dumps(results, indent=2))
