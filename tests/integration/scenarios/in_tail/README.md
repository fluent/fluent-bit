# `in_tail` Integration Scenario

This scenario is a production-hardening integration suite for `plugins/in_tail`.

It exercises real Fluent Bit process behavior through the Python integration
harness, not just unit or runtime-library coverage.

## Current Coverage

- discovery of new files after startup
- discovery of new files from tail when `read_newly_discovered_files_from_head` is disabled
- startup with `read_from_head: false`
- rename rotation with writes to both old and new files
- repeated rename rotation on the same path
- copytruncate with a stale writer file descriptor
- symlink target rotation
- polling mode with `inotify_watcher: false`
- `db.compare_filename` restart behavior
- parser mode
- docker mode
- multiline core mode
- `skip_long_lines`
- `truncate_long_lines`
- `rotate_wait` behavior before and after purge
- delete and recreate of the same path
- restart with DB offset reuse
- copytruncate across restart
- partial-line completion across restart
- multi-file rapid rotation
- gzip static file ingestion
- generic input encoding conversion
- `exclude_path` filtering
- `ignore_older`
- `ignore_active_older_files`
- delayed readability after startup
- `max_open_files` limits, deferred discovery, slot release, and 75% usage warnings
- a shared file budget with four threaded Tail inputs and multiple output workers

## Notes

- The polling-mode scenarios are intended to approximate remote or shared
  filesystem deployments where `inotify` is not reliable or not available.
- Database-backed scenarios use `db.journal_mode: DELETE` because WAL is not
  suitable for shared network filesystems.
- Database-backed restart scenarios also validate automatic schema upgrade for
  persisted offset-marker metadata used to detect copytruncate/rewrite cases
  across restarts.
- This suite still cannot fully replace testing on a real NFS mount or kernel
  fault-injection environment. Those remain separate environment-dependent
  validation phases.

## Open-file budget

Set `max_open_files: 1024` on a Tail input to limit all Tail inputs in the process
to 1,024 simultaneously open monitored files in total. Omitted or zero values
inherit the shared limit; if no input specifies a positive value, it is unlimited.
Positive values must agree, and negative or conflicting values fail startup.
The limit is resolved across all inputs before the first input opens files.
Separate embedded engines in the same process also share the active pool; a
conflicting positive limit cannot replace it until its last user has exited.

Static, continuously monitored, and retained rotated files share the budget.
Database, watcher, and other process handles are outside it. CFL atomic
compare-and-exchange reserves capacity before opening, without fixed shares per
worker. Failed opens, failed initialization, and file removal return their slots.

At 75% shared usage (rounded up to a whole file), Tail warns once and continues
opening files up to the hard cap. The warning is rearmed when usage falls below
75%. At the cap, excess files are retried on subsequent `refresh_interval` scans.
Reaching EOF does not free a slot. There is no fairness guarantee between inputs;
files that disappear before admission may never be read. Existing offset and
read-from-head settings still determine where an admitted file starts reading.
Saved database offsets for deferred files are retained during startup cleanup.
