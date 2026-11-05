# Local decision examples

Run from the repository root with an FTS-enabled build:

```sh
build/bin/fluent-bit --dry-run -c plugins/processor_fts/examples/recipes/dedupe.yaml
build/bin/fluent-bit -c plugins/processor_fts/examples/recipes/dedupe.yaml
```

Dedupe receives five synthetic repetitions and emits the first, with its password
redacted. Stop the process after the demonstration. `throttle.yaml` sends a
synthetic burst and limits it using two tokens/second and a burst capacity of ten.
Its precise output count depends on scheduling; virtual-clock tests establish
the exact boundary behavior.

Replace the dummy source with your source and choose trusted tenant/key selectors.
Keep privacy before the final decision. Missing keys fail closed in these examples.
Capacity overflow explicitly passes untracked records, so these examples implement
best-effort telemetry reduction, not a security or billing quota.

State is local to the processor and volatile across restart, reload and shutdown.
A successful local commit can precede an outer encode/storage failure. The
[FTS README](../../README.md#local-deduplication-and-keyed-throttling) describes
limits, identity, metrics and these failure semantics. Focused integration tests
are in `tests/integration/scenarios/processor_fts/tests/test_fts_recipe_state.py`;
virtual-clock boundary tests are in `tests/internal/fts.c`.
