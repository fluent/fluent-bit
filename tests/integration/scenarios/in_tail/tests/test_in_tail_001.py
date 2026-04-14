import gzip
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.test_service import FluentBitTestService


class PersistentWriter:
    def __init__(self, path, *, append=False):
        flags = os.O_WRONLY | os.O_CREAT
        if append:
            flags |= os.O_APPEND

        self.path = path
        self.fd = os.open(path, flags, 0o644)

    def write_line(self, text):
        os.write(self.fd, f"{text}\n".encode("utf-8"))
        os.fsync(self.fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Service:
    def __init__(self, config_file, *, tail_path, db_path):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.tail_path = str(tail_path)
        self.db_path = str(db_path)
        self.parsers_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config/parsers_tail_it.conf")
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "TAIL_TEST_PATH": self.tail_path,
                "TAIL_TEST_DB": self.db_path,
                "PARSERS_FILE_TEST": self.parsers_file,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )
        self.flb = None

    def _start_receiver(self, service):
        http_server_run(service.test_suite_http_port)
        self.service.wait_for_http_endpoint(
            f"http://127.0.0.1:{service.test_suite_http_port}/ping",
            timeout=10,
            interval=0.5,
        )

    def _stop_receiver(self, service):
        try:
            requests.post(
                f"http://127.0.0.1:{service.test_suite_http_port}/shutdown",
                timeout=2,
            )
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def wait_for_records(self, minimum_count, timeout=15):
        def enough_records():
            records = flatten_records(data_storage["payloads"])

            if len(records) >= minimum_count:
                return records

            return None

        return self.service.wait_for_condition(
            enough_records,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} tailed records",
        )

    def assert_no_new_records_for(self, expected_count, quiet_period=3):
        deadline = time.time() + quiet_period

        while time.time() < deadline:
            records = flatten_records(data_storage["payloads"])
            assert len(records) == expected_count
            time.sleep(0.5)


def flatten_records(payloads):
    records = []

    for payload in payloads:
        if isinstance(payload, list):
            records.extend(payload)
        elif payload is not None:
            records.append(payload)

    return records


def write_and_sync(path, content):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def write_long_line(path, size):
    chunk = "0123456789abcdef0123456789abcdef"
    remaining = size
    parts = []

    while remaining > 0:
        piece = chunk[: min(len(chunk), remaining)]
        parts.append(piece)
        remaining -= len(piece)

    write_and_sync(path, "".join(parts) + "\n")


def extract_logs(records):
    return [record["log"] for record in records]


def assert_log_set(records, expected_logs):
    logs = extract_logs(records)

    assert sorted(logs) == sorted(expected_logs)
    for expected in expected_logs:
        assert logs.count(expected) == 1


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory(prefix="flb-tail-it-") as tmpdir:
        yield Path(tmpdir)


def test_in_tail_discovers_new_files_from_head(workspace):
    log_dir = workspace / "logs"
    log_dir.mkdir()

    service = Service(
        "tail_inotify.yaml",
        tail_path=log_dir / "*.log",
        db_path=workspace / "tail.db",
    )

    try:
        service.start()

        discovered = log_dir / "discovered.log"
        discovered.write_text("discover-1\ndiscover-2\n", encoding="utf-8")

        records = service.wait_for_records(2)
        assert_log_set(records[:2], ["discover-1", "discover-2"])
        assert all(record["file"] == str(discovered) for record in records[:2])

        with discovered.open("a", encoding="utf-8") as handle:
            handle.write("discover-3\n")
            handle.flush()
            os.fsync(handle.fileno())

        records = service.wait_for_records(3)
        assert_log_set(records, ["discover-1", "discover-2", "discover-3"])
    finally:
        service.stop()


def test_in_tail_newly_discovered_files_can_start_from_tail(workspace):
    log_dir = workspace / "new-tail"
    log_dir.mkdir()

    service = Service(
        "tail_inotify_new_files_from_tail.yaml",
        tail_path=log_dir / "*.log",
        db_path=workspace / "tail.db",
    )

    try:
        service.start()

        discovered = log_dir / "discovered.log"
        discovered.write_text("old-1\nold-2\n", encoding="utf-8")

        service.assert_no_new_records_for(0, quiet_period=3)

        write_and_sync(discovered, "new-1\n")
        records = service.wait_for_records(1)
    finally:
        service.stop()

    assert_log_set(records, ["new-1"])
    assert records[0]["offset"] > 0


def test_in_tail_existing_file_can_start_from_tail_on_startup(workspace):
    log_file = workspace / "startup-tail.log"
    db_path = workspace / "tail.db"

    log_file.write_text("old-1\nold-2\n", encoding="utf-8")

    service = Service(
        "tail_inotify_read_from_tail.yaml",
        tail_path=log_file,
        db_path=db_path,
    )

    try:
        service.start()
        service.assert_no_new_records_for(0, quiet_period=3)

        write_and_sync(log_file, "new-1\n")
        records = service.wait_for_records(1, timeout=20)
    finally:
        service.stop()

    assert_log_set(records, ["new-1"])
    assert records[0]["offset"] > 0


def test_in_tail_follows_rename_rotation(workspace):
    active_log = workspace / "app.log"
    db_path = workspace / "tail.db"

    writer_old = PersistentWriter(active_log)
    writer_old.write_line("before-rotate")

    service = Service("tail_inotify.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        rotated_log = workspace / "app.log.1"
        os.rename(active_log, rotated_log)

        writer_new = PersistentWriter(active_log, append=True)
        try:
            writer_old.write_line("after-rotate-old-file")
            writer_new.write_line("after-rotate-new-file")
            records = service.wait_for_records(3)
        finally:
            writer_new.close()

        assert_log_set(
            records,
            [
                "before-rotate",
                "after-rotate-old-file",
                "after-rotate-new-file",
            ],
        )
    finally:
        writer_old.close()
        service.stop()


def test_in_tail_handles_multiple_rename_rotations(workspace):
    active_log = workspace / "multi-rotate.log"
    db_path = workspace / "tail.db"

    writer_first = PersistentWriter(active_log)
    writer_first.write_line("before-rotate-1")

    service = Service("tail_inotify.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        first_rotated = workspace / "multi-rotate.log.1"
        os.rename(active_log, first_rotated)

        writer_second = PersistentWriter(active_log, append=True)
        try:
            writer_first.write_line("after-rotate-1-old-file")
            writer_second.write_line("after-rotate-1-new-file")
            service.wait_for_records(3, timeout=20)

            second_rotated = workspace / "multi-rotate.log.2"
            os.rename(active_log, second_rotated)

            writer_third = PersistentWriter(active_log, append=True)
            try:
                writer_second.write_line("after-rotate-2-old-file")
                writer_third.write_line("after-rotate-2-new-file")
                records = service.wait_for_records(5, timeout=20)
            finally:
                writer_third.close()
        finally:
            writer_second.close()

        assert_log_set(
            records,
            [
                "before-rotate-1",
                "after-rotate-1-old-file",
                "after-rotate-1-new-file",
                "after-rotate-2-old-file",
                "after-rotate-2-new-file",
            ],
        )
    finally:
        writer_first.close()
        service.stop()


def test_in_tail_handles_copytruncate_with_stale_writer(workspace):
    active_log = workspace / "copytruncate.log"
    archive_log = workspace / "copytruncate.log.1"
    db_path = workspace / "tail.db"

    writer = PersistentWriter(active_log)
    writer.write_line("before-truncate-1")
    writer.write_line("before-truncate-2")

    service = Service("tail_inotify.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(2)

        shutil.copyfile(active_log, archive_log)
        os.truncate(active_log, 0)

        writer.write_line("after-truncate")

        records = service.wait_for_records(3)
        assert_log_set(
            records,
            ["before-truncate-1", "before-truncate-2", "after-truncate"],
        )
        assert all("\x00" not in record["log"] for record in records)
    finally:
        writer.close()
        service.stop()


def test_in_tail_handles_symlink_target_rotation(workspace):
    target_one = workspace / "target-one.log"
    target_two = workspace / "target-two.log"
    symlink_path = workspace / "current.log"
    db_path = workspace / "tail.db"

    target_one.write_text("symlink-before-rotate\n", encoding="utf-8")
    symlink_path.symlink_to(target_one)

    old_target_writer = PersistentWriter(target_one, append=True)

    service = Service("tail_inotify.yaml", tail_path=symlink_path, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        target_two.write_text("", encoding="utf-8")
        new_link = workspace / "current.log.next"
        new_link.symlink_to(target_two)
        os.replace(new_link, symlink_path)

        new_target_writer = PersistentWriter(target_two, append=True)
        try:
            old_target_writer.write_line("symlink-old-target")
            new_target_writer.write_line("symlink-new-target")
            records = service.wait_for_records(3, timeout=20)
        finally:
            new_target_writer.close()

        assert_log_set(
            records,
            [
                "symlink-before-rotate",
                "symlink-old-target",
                "symlink-new-target",
            ],
        )
    finally:
        old_target_writer.close()
        service.stop()


def test_in_tail_stat_backend_covers_nfs_style_polling(workspace):
    active_log = workspace / "nfs-style.log"
    db_path = workspace / "tail.db"

    writer_old = PersistentWriter(active_log)
    writer_old.write_line("poll-before-rotate")

    service = Service("tail_stat.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        rotated_log = workspace / "nfs-style.log.1"
        os.rename(active_log, rotated_log)

        writer_new = PersistentWriter(active_log, append=True)
        try:
            writer_old.write_line("poll-old-file")
            writer_new.write_line("poll-new-file")
            records = service.wait_for_records(3, timeout=20)
        finally:
            writer_new.close()

        assert_log_set(
            records,
            ["poll-before-rotate", "poll-old-file", "poll-new-file"],
        )
    finally:
        writer_old.close()
        service.stop()


def test_in_tail_db_compare_filename_replays_renamed_file_after_restart(workspace):
    source_log = workspace / "db-source.log"
    moved_log = workspace / "db-moved.log"
    db_path = workspace / "tail.db"

    source_log.write_text("before-restart\n", encoding="utf-8")

    first_run = Service(
        "tail_stat_db_compare_filename.yaml",
        tail_path=source_log,
        db_path=db_path,
    )

    try:
        first_run.start()
        records = first_run.wait_for_records(1)
        assert_log_set(records, ["before-restart"])
    finally:
        first_run.stop()

    os.rename(source_log, moved_log)

    second_run = Service(
        "tail_stat_db_compare_filename.yaml",
        tail_path=moved_log,
        db_path=db_path,
    )

    try:
        second_run.start()
        records = second_run.wait_for_records(1, timeout=20)
        assert_log_set(records, ["before-restart"])

        with moved_log.open("a", encoding="utf-8") as handle:
            handle.write("after-restart\n")
            handle.flush()
            os.fsync(handle.fileno())

        records = second_run.wait_for_records(2, timeout=20)
        assert_log_set(records, ["before-restart", "after-restart"])
    finally:
        second_run.stop()


def test_in_tail_parser_mode_structures_records(workspace):
    log_file = workspace / "apache.log"
    db_path = workspace / "tail.db"

    write_and_sync(
        log_file,
        '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326\n',
    )

    service = Service("tail_parser.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(1)
    finally:
        service.stop()

    record = records[0]
    assert record["host"] == "127.0.0.1"
    assert record["user"] == "frank"
    assert record["method"] == "GET"
    assert record["path"] == "/apache_pb.gif"
    assert record["code"] == "200"
    assert record["size"] == "2326"
    assert record["file"] == str(log_file)
    assert "offset" in record


def test_in_tail_multiline_mode_combines_stacktrace(workspace):
    log_file = workspace / "multiline.log"
    db_path = workspace / "tail.db"

    write_and_sync(
        log_file,
        "[2025-06-16 20:42:22,291] ERROR first line\n"
        " at com.example.First.method(First.java:10)\n"
        " at com.example.Second.method(Second.java:20)\n"
        "[2025-06-16 20:45:29,234] INFO next line\n",
    )

    service = Service("tail_multiline.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(2, timeout=20)
    finally:
        service.stop()

    logs = extract_logs(records)
    combined = next(log for log in logs if "First.method" in log)
    single = next(log for log in logs if "INFO next line" in log)

    assert "ERROR first line" in combined
    assert "Second.method" in combined
    assert combined.count("\n") >= 2
    assert "INFO next line" in single


def test_in_tail_skip_long_lines_keeps_surrounding_records(workspace):
    log_file = workspace / "skip-long.log"
    db_path = workspace / "tail.db"

    write_and_sync(log_file, "before-long-line\n")
    write_long_line(log_file, 10 * 1024)
    write_and_sync(log_file, "after-long-line\n")

    service = Service("tail_skip_long_lines.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(2, timeout=20)
    finally:
        service.stop()

    assert_log_set(records, ["before-long-line", "after-long-line"])


def test_in_tail_truncate_long_lines_emits_truncated_record_and_continues(workspace):
    log_file = workspace / "truncate-long.log"
    db_path = workspace / "tail.db"

    write_and_sync(log_file, "before-long-line\n")
    write_long_line(log_file, 10 * 1024)
    write_and_sync(log_file, "after-long-line\n")

    service = Service("tail_truncate_long_lines.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(3, timeout=20)
    finally:
        service.stop()

    logs = extract_logs(records)
    assert "before-long-line" in logs
    assert "after-long-line" in logs

    truncated = [log for log in logs if log not in {"before-long-line", "after-long-line"}]
    assert len(truncated) == 1
    assert len(truncated[0]) <= 4095
    assert len(truncated[0]) > 0


def test_in_tail_rotate_wait_keeps_old_inode_then_purges_it(workspace):
    active_log = workspace / "rotate-wait.log"
    db_path = workspace / "tail.db"

    writer_old = PersistentWriter(active_log)
    writer_old.write_line("before-rotate")

    service = Service("tail_rotate_wait_short.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        rotated_log = workspace / "rotate-wait.log.1"
        os.rename(active_log, rotated_log)

        writer_new = PersistentWriter(active_log, append=True)
        try:
            time.sleep(1)
            writer_old.write_line("late-before-purge")
            writer_new.write_line("new-file-line")
            records = service.wait_for_records(3, timeout=20)
            assert_log_set(records, ["before-rotate", "late-before-purge", "new-file-line"])

            time.sleep(3)
            writer_old.write_line("too-late-after-purge")
            service.assert_no_new_records_for(3, quiet_period=4)
        finally:
            writer_new.close()
    finally:
        writer_old.close()
        service.stop()


def test_in_tail_delete_and_recreate_same_path_is_reingested(workspace):
    active_log = workspace / "recreate.log"
    db_path = workspace / "tail.db"

    writer_old = PersistentWriter(active_log)
    writer_old.write_line("before-delete")

    service = Service("tail_stat.yaml", tail_path=active_log, db_path=db_path)

    try:
        service.start()
        service.wait_for_records(1)

        os.unlink(active_log)
        writer_old.close()

        time.sleep(3)

        write_and_sync(active_log, "after-recreate\n")
        records = service.wait_for_records(2, timeout=20)
        assert_log_set(records, ["before-delete", "after-recreate"])
    finally:
        writer_old.close()
        service.stop()


def test_in_tail_restart_resumes_from_db_offset(workspace):
    log_file = workspace / "resume.log"
    db_path = workspace / "tail.db"

    write_and_sync(log_file, "first-line\n")

    first_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        first_run.start()
        records = first_run.wait_for_records(1)
        assert_log_set(records, ["first-line"])
    finally:
        first_run.stop()

    write_and_sync(log_file, "second-line\n")

    second_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        second_run.start()
        records = second_run.wait_for_records(1, timeout=20)
        assert_log_set(records, ["second-line"])
    finally:
        second_run.stop()


def test_in_tail_copytruncate_across_restart_reads_new_content_only(workspace):
    log_file = workspace / "restart-copytruncate.log"
    archived = workspace / "restart-copytruncate.log.1"
    db_path = workspace / "tail.db"

    write_and_sync(log_file, "before-restart\n")

    first_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        first_run.start()
        records = first_run.wait_for_records(1)
        assert_log_set(records, ["before-restart"])
    finally:
        first_run.stop()

    shutil.copyfile(log_file, archived)
    os.truncate(log_file, 0)
    write_and_sync(log_file, "after-restart-truncate\n")

    second_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        second_run.start()
        records = second_run.wait_for_records(1, timeout=20)
        assert_log_set(records, ["after-restart-truncate"])
    finally:
        second_run.stop()


def test_in_tail_partial_line_across_restart_is_completed_once(workspace):
    log_file = workspace / "partial-restart.log"
    db_path = workspace / "tail.db"

    log_file.write_text("partial", encoding="utf-8")

    first_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        first_run.start()
        first_run.assert_no_new_records_for(0, quiet_period=3)
    finally:
        first_run.stop()

    write_and_sync(log_file, " line\n")

    second_run = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)
    try:
        second_run.start()
        records = second_run.wait_for_records(1, timeout=20)
    finally:
        second_run.stop()

    assert_log_set(records, ["partial line"])


def test_in_tail_db_schema_upgrade_is_automatic(workspace):
    log_file = workspace / "schema-upgrade.log"
    db_path = workspace / "tail.db"
    initial = "before-upgrade\n"
    appended = "after-upgrade\n"

    log_file.write_text(initial + appended, encoding="utf-8")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE in_tail_files (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                offset INTEGER,
                inode INTEGER,
                created INTEGER,
                rotated INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            INSERT INTO in_tail_files (name, offset, inode, created, rotated)
            VALUES (?, ?, ?, ?, 0)
            """,
            (
                str(log_file),
                len(initial),
                os.stat(log_file).st_ino,
                int(time.time()),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    service = Service("tail_stat.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(1, timeout=20)
    finally:
        service.stop()

    assert_log_set(records, ["after-upgrade"])

    conn = sqlite3.connect(db_path)
    try:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(in_tail_files)")
        }
    finally:
        conn.close()

    assert "offset_marker" in columns
    assert "offset_marker_size" in columns


def test_in_tail_multi_file_rapid_rotation(workspace):
    log_dir = workspace / "rapid"
    log_dir.mkdir()
    db_path = workspace / "tail.db"

    active_files = [log_dir / f"rapid-{index}.log" for index in range(3)]
    old_writers = []

    for index, path in enumerate(active_files):
        writer = PersistentWriter(path)
        writer.write_line(f"before-{index}")
        old_writers.append(writer)

    service = Service("tail_inotify.yaml", tail_path=log_dir / "*.log", db_path=db_path)

    try:
        service.start()
        service.wait_for_records(3, timeout=20)

        new_writers = []
        try:
            for index, path in enumerate(active_files):
                rotated = log_dir / f"rapid-{index}.log.1"
                os.rename(path, rotated)

                new_writer = PersistentWriter(path, append=True)
                new_writers.append(new_writer)

                old_writers[index].write_line(f"old-after-{index}")
                new_writer.write_line(f"new-after-{index}")

            records = service.wait_for_records(9, timeout=30)
        finally:
            for writer in new_writers:
                writer.close()

        expected = []
        for index in range(3):
            expected.extend(
                [f"before-{index}", f"old-after-{index}", f"new-after-{index}"]
            )

        assert_log_set(records, expected)
    finally:
        for writer in old_writers:
            writer.close()
        service.stop()


def test_in_tail_reads_gzip_static_file(workspace):
    gzip_file = workspace / "compressed.log.gz"
    db_path = workspace / "tail.db"

    with gzip.open(gzip_file, "wt", encoding="utf-8") as handle:
        handle.write("gzip-line-1\n")
        handle.write("gzip-line-2\n")

    service = Service("tail_gzip.yaml", tail_path=gzip_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(2, timeout=20)
    finally:
        service.stop()

    assert_log_set(records, ["gzip-line-1", "gzip-line-2"])


def test_in_tail_exclude_path_skips_matching_files(workspace):
    log_dir = workspace / "exclude"
    log_dir.mkdir()
    db_path = workspace / "tail.db"

    keep_file = log_dir / "keep.log"
    ignored_file = log_dir / "ignored.skip"

    keep_file.write_text("keep-me\n", encoding="utf-8")
    ignored_file.write_text("ignore-me\n", encoding="utf-8")

    service = Service("tail_exclude_path.yaml", tail_path=log_dir / "*", db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(1, timeout=20)
        service.assert_no_new_records_for(1, quiet_period=3)
    finally:
        service.stop()

    assert_log_set(records, ["keep-me"])
    assert records[0]["file"] == str(keep_file)


def test_in_tail_ignore_older_skips_stale_files(workspace):
    stale_file = workspace / "stale.log"
    db_path = workspace / "tail.db"

    stale_file.write_text("too-old\n", encoding="utf-8")
    old_time = time.time() - 10
    os.utime(stale_file, (old_time, old_time))

    service = Service("tail_ignore_older.yaml", tail_path=stale_file, db_path=db_path)

    try:
        service.start()
        service.assert_no_new_records_for(0, quiet_period=4)
    finally:
        service.stop()


def test_in_tail_ignore_active_older_files_stops_following_aged_file(workspace):
    log_file = workspace / "active-aged.log"
    db_path = workspace / "tail.db"

    write_and_sync(log_file, "first-line\n")

    service = Service("tail_ignore_active_older.yaml", tail_path=log_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(1, timeout=20)
        assert_log_set(records, ["first-line"])

        time.sleep(4)
        service.assert_no_new_records_for(1, quiet_period=4)
        write_and_sync(log_file, "second-line\n")
        service.assert_no_new_records_for(1, quiet_period=4)
    finally:
        service.stop()


def test_in_tail_docker_mode_parses_and_flushes_docker_json_stream(workspace):
    docker_file = workspace / "docker.log"
    db_path = workspace / "tail.db"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

    payload = (
        f'{{"log":"docker hello\\\\n","stream":"stdout","time":"{ts}"}}'
        "\n"
        f'{{"log":"docker bye\\\\n","stream":"stderr","time":"{ts}"}}'
        "\n"
    )
    docker_file.write_text(payload, encoding="utf-8")

    service = Service("tail_docker_mode.yaml", tail_path=docker_file, db_path=db_path)

    try:
        service.start()
        service.service.wait_for_condition(
            lambda: len(data_storage["requests"]) >= 1,
            timeout=20,
            interval=0.5,
            description="docker mode request",
        )
        records = flatten_records(data_storage["payloads"])
    finally:
        service.stop()

    assert len(records) == 1
    record = records[0]
    assert record["log"] == "docker hello\\ndocker bye\\n"
    assert record["stream"] == "stderr"
    assert record["file"] == str(docker_file)
    assert record["offset"] > 0


def test_in_tail_generic_encoding_shiftjis(workspace):
    encoded_file = workspace / "shiftjis.log"
    db_path = workspace / "tail.db"
    expected_text = "こんにちは世界"

    with open(encoded_file, "wb") as handle:
        handle.write((expected_text + "\n").encode("shift_jis"))
        handle.flush()
        os.fsync(handle.fileno())

    service = Service("tail_generic_encoding.yaml", tail_path=encoded_file, db_path=db_path)

    try:
        service.start()
        records = service.wait_for_records(1, timeout=20)
    finally:
        service.stop()

    assert_log_set(records, [expected_text])


def test_in_tail_discovers_file_after_permissions_are_restored(workspace):
    log_dir = workspace / "permissions"
    log_dir.mkdir()
    delayed_file = log_dir / "delayed.log"
    db_path = workspace / "tail.db"

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("permission restoration test is not reliable when run as root")

    delayed_file.write_text("became-readable\n", encoding="utf-8")
    delayed_file.chmod(0)

    service = Service("tail_stat.yaml", tail_path=log_dir / "*.log", db_path=db_path)

    try:
        service.start()
        time.sleep(2)
        delayed_file.chmod(0o644)
        records = service.wait_for_records(1, timeout=20)
    finally:
        delayed_file.chmod(0o644)
        service.stop()

    assert_log_set(records, ["became-readable"])
