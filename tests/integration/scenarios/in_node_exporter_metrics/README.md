# Node exporter systemd snapshots

This scenario runs the systemd collector against a private D-Bus service and
captures its output with a local OTLP receiver. It requires Linux,
`dbus-daemon`, the Python dependencies from `tests/integration/requirements.txt`,
and a Fluent Bit build with systemd D-Bus support. It does not access the host's
systemd manager.

The tests verify that unchanged values receive new sample timestamps, while
disappeared or unloaded units, obsolete label sets, and unavailable task counts
stop being exported after a successful scan. Failed scans preserve existing
samples; expiration resumes when collection recovers. Global systemd metrics,
metric values, start timestamps, and labels added by a processor are also
checked.

From the repository root:

```sh
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/in_node_exporter_metrics -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/in_node_exporter_metrics -q
```
