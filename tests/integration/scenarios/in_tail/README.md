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
