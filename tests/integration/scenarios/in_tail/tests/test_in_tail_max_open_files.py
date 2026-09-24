"""Shared admission, pressure reclamation, and dormant file resumption."""
import os
import sys
from pathlib import Path

import pytest

from test_in_tail_001 import Service, assert_log_set, workspace, write_and_sync
from utils.fluent_bit_manager import FluentBitStartupError


def budget_service(workspace, limit):
    template = Path(__file__).parent.parent / "config/tail_rotate_wait_short.yaml"
    config = template.read_text(encoding="utf-8")
    if limit is not None:
        config = config.replace("      tag: tail.integration",
                                f"      max_open_files: {limit}\n      tag: tail.integration")
    config_path = workspace / "budget.yaml"
    config_path.write_text(config, encoding="utf-8")
    return Service(config_path, tail_path=workspace / "*.log", db_path=workspace / "tail.db")


def wait_for_dormant(service, path):
    message = f"releasing dormant file at 75% budget usage: {path}"
    service.service.wait_for_condition(
        lambda: message in Path(service.flb.log_file).read_text(encoding="utf-8"),
        timeout=30, interval=0.2, description="dormant file release",
    )


@pytest.mark.parametrize("limit", [None, 0, 1, 2])
@pytest.mark.parametrize("database", [False, True])
def test_max_open_files_drains_and_resumes(workspace, limit, database):
    paths = [workspace / f"{index}.log" for index in range(5)]
    for index, path in enumerate(paths):
        path.write_text(f"initial-{index}\n", encoding="utf-8")
    service = budget_service(workspace, limit)
    if not database:
        config = Path(service.config_file)
        config.write_text("\n".join(line for line in config.read_text().splitlines()
                                     if not line.strip().startswith("db")) + "\n")
    try:
        service.start()
        records = service.wait_for_records(5, timeout=30)
        service.assert_no_new_records_for(5)
        assert_log_set(records, [f"initial-{i}" for i in range(5)])
        log = Path(service.flb.log_file).read_text()
        if limit:
            assert "releasing dormant file" in log
        else:
            assert "releasing dormant file" not in log
        for index, path in enumerate(paths):
            write_and_sync(path, f"append-{index}\n")
        records = service.wait_for_records(10, timeout=30)
        service.assert_no_new_records_for(10)
        assert_log_set(records, [f"initial-{i}" for i in range(5)] +
                       [f"append-{i}" for i in range(5)])
    finally:
        service.stop()


@pytest.mark.parametrize("database", [False, True])
@pytest.mark.parametrize("change", ["truncate", "regrow", "replace", "same_size"])
def test_max_open_files_dormant_changed_file(workspace, database, change):
    path = workspace / "0.log"
    path.write_text("original-long-record\n", encoding="utf-8")
    os.utime(path, ns=(1760000000100000000, 1760000000100000000))
    service = budget_service(workspace, 1)
    config = Path(service.config_file)
    text = config.read_text().replace("read_newly_discovered_files_from_head: true",
                                     "read_newly_discovered_files_from_head: false")
    if not database:
        text = "\n".join(line for line in text.splitlines()
                         if not line.strip().startswith("db")) + "\n"
    config.write_text(text)
    try:
        service.start()
        service.wait_for_records(1)
        wait_for_dormant(service, path)
        if change == "replace":
            path.rename(path.with_suffix(".retired"))
        replacement = "new" if change == "truncate" else "replacement-record-longer-than-before"
        if change == "same_size":
            replacement = "modified-long-record"
        path.write_text(replacement + "\n", encoding="utf-8")
        if change == "same_size":
            os.utime(path, ns=(1760000000200000000, 1760000000200000000))
        records = service.wait_for_records(2, timeout=30)
        service.assert_no_new_records_for(2)
        assert_log_set(records, ["original-long-record", replacement])
    finally:
        service.stop()



def test_max_open_files_warning_does_not_throttle(workspace):
    service = budget_service(workspace, 4)

    def log_text():
        return Path(service.flb.log_file).read_text(encoding="utf-8")

    warning = "open file usage reached 75% of max_open_files"
    try:
        service.start()
        for index in range(2):
            (workspace / f"{index}.log").write_text(f"line-{index}\npartial", encoding="utf-8")
        service.wait_for_records(2)
        assert warning not in log_text()

        (workspace / "2.log").write_text("line-2\npartial", encoding="utf-8")
        service.wait_for_records(3)
        assert log_text().count(warning) == 1

        (workspace / "3.log").write_text("line-3\npartial", encoding="utf-8")
        service.wait_for_records(4)
        assert log_text().count(warning) == 1

        (workspace / "4.log").write_text("line-4\npartial", encoding="utf-8")
        service.assert_no_new_records_for(4)
        assert "max_open_files=4 reached; deferring" in log_text()

        for index in range(5):
            path = workspace / f"{index}.log"
            path.rename(path.with_suffix(".retired"))
        service.service.wait_for_condition(
            lambda: log_text().count("removing file name") >= 4,
            timeout=30, interval=0.5, description="budget slots released",
        )
        for index in range(3):
            (workspace / f"new-{index}.log").write_text(f"new-{index}\npartial", encoding="utf-8")
        service.wait_for_records(7)
        assert log_text().count(warning) == 2
    finally:
        service.stop()


def test_max_open_files_rejects_negative(workspace):
    service = budget_service(workspace, -1)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        log_file = service.service.flb.log_file
        assert "max_open_files must be >= 0" in Path(log_file).read_text(encoding="utf-8")
    finally:
        service.stop()


def test_max_open_files_failed_open_releases_slot(workspace):
    if sys.platform == "win32" or os.geteuid() == 0:
        pytest.skip("requires POSIX file permissions enforced for a non-root user")

    unreadable = workspace / "0.log"
    unreadable.write_text("unreadable\n", encoding="utf-8")
    unreadable.chmod(0)
    (workspace / "1.log").write_text("readable\n", encoding="utf-8")
    service = budget_service(workspace, 1)
    try:
        service.start()
        records = service.wait_for_records(1)
        assert_log_set(records, ["readable"])
        log = Path(service.flb.log_file).read_text(encoding="utf-8")
        assert f"cannot open {unreadable}" in log
    finally:
        unreadable.chmod(0o600)
        service.stop()


@pytest.mark.parametrize("inherit", [False, True])
def test_max_open_files_shared_threaded_instances(workspace, inherit):
    import copy
    import yaml

    service = budget_service(workspace, 2)
    config_path = Path(service.config_file)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    template = config["pipeline"]["inputs"][0]
    inputs = []
    for index in range(4):
        directory = workspace / str(index)
        directory.mkdir()
        instance = copy.deepcopy(template)
        instance["path"] = str(directory / "*.log")
        instance["db"] = str(directory / "tail.db")
        instance["threaded"] = True
        if inherit and index == 0:
            instance.pop("max_open_files")
        elif inherit and index < 3:
            instance["max_open_files"] = 0
        inputs.append(instance)
    config["pipeline"]["inputs"] = inputs
    config["pipeline"]["outputs"][0]["workers"] = 2
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    def populate():
        for index in range(4):
            for number in range(2):
                (workspace / str(index) / f"{number}.log").write_text(
                    f"{index}-{number}\n", encoding="utf-8")

    if inherit:
        # The last input's setting must constrain the first input's initial scan.
        populate()
    try:
        service.start()
        if not inherit:
            # All four owner threads can discover files concurrently.
            populate()
        records = service.wait_for_records(8, timeout=45)
        service.assert_no_new_records_for(8)
        assert_log_set(records, [f"{index}-{number}" for index in range(4)
                                for number in range(2)])
    finally:
        service.stop()


def test_max_open_files_conflicting_limits(workspace):
    import copy
    import yaml

    service = budget_service(workspace, 1)
    config_path = Path(service.config_file)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    second = copy.deepcopy(config["pipeline"]["inputs"][0])
    second["max_open_files"] = 2
    second["db"] = str(workspace / "second.db")
    config["pipeline"]["inputs"].append(second)
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        log = Path(service.service.flb.log_file).read_text(encoding="utf-8")
        assert "conflicting max_open_files values" in log
    finally:
        service.stop()


def test_max_open_files_preserves_deferred_database_offsets(workspace):
    for index in range(2):
        (workspace / f"{index}.log").write_text(f"initial-{index}\n", encoding="utf-8")
    first = budget_service(workspace, 0)
    try:
        first.start()
        first.wait_for_records(2)
    finally:
        first.stop()

    for index in range(2):
        write_and_sync(workspace / f"{index}.log", f"appended-{index}\n")
    second = budget_service(workspace, 1)
    try:
        second.start()
        records = second.wait_for_records(2, timeout=30)
        second.assert_no_new_records_for(2)
        assert_log_set(records, ["appended-0", "appended-1"])
    finally:
        second.stop()


def test_max_open_files_preserves_ignored_offset_while_full(workspace):
    import time

    service = budget_service(workspace, 1)
    config_path = Path(service.config_file)
    config = config_path.read_text(encoding="utf-8").replace(
        "      rotate_wait: 2", "      rotate_wait: 2\n      ignore_older: 30s")
    config_path.write_text(config, encoding="utf-8")
    active = workspace / "0.log"
    aged = workspace / "1.log"
    try:
        service.start()
        active.write_text("active\npartial", encoding="utf-8")
        aged.write_text("old-content\n", encoding="utf-8")
        old_time = time.time() - 120
        os.utime(aged, (old_time, old_time))
        service.wait_for_records(1)
        service.assert_no_new_records_for(1)

        write_and_sync(aged, "new-content\n")
        service.assert_no_new_records_for(1)
        active.rename(active.with_suffix(".retired"))
        records = service.wait_for_records(2, timeout=30)
        service.assert_no_new_records_for(2)
        assert_log_set(records, ["active", "new-content"])
    finally:
        service.stop()


def test_max_open_files_partial_record_pins_slot(workspace):
    path = workspace / "0.log"
    path.write_text("first\npartial", encoding="utf-8")
    (workspace / "1.log").write_text("deferred\n", encoding="utf-8")
    service = budget_service(workspace, 1)
    try:
        service.start()
        service.wait_for_records(1)
        service.assert_no_new_records_for(1)
        assert "releasing dormant file" not in Path(service.flb.log_file).read_text()
        write_and_sync(path, "-completed\n")
        records = service.wait_for_records(3, timeout=30)
        service.assert_no_new_records_for(3)
        assert_log_set(records, ["first", "partial-completed", "deferred"])
    finally:
        service.stop()


def test_max_open_files_reclaims_at_three_quarters(workspace):
    service = budget_service(workspace, 4)
    try:
        service.start()
        for index in range(2):
            (workspace / f"{index}.log").write_text(f"line-{index}\n", encoding="utf-8")
        service.wait_for_records(2)
        service.assert_no_new_records_for(2)
        assert "releasing dormant file" not in Path(service.flb.log_file).read_text()
        (workspace / "2.log").write_text("line-2\n", encoding="utf-8")
        service.wait_for_records(3)
        service.service.wait_for_condition(
            lambda: "releasing dormant file" in Path(service.flb.log_file).read_text(),
            timeout=30, interval=0.2, description="reclamation before the hard cap",
        )
        service.assert_no_new_records_for(3)
        log = Path(service.flb.log_file).read_text()
        assert log.count("releasing dormant file") == 1
        assert "max_open_files=4 reached; deferring" not in log
    finally:
        service.stop()


@pytest.mark.parametrize("database", [False, True])
def test_max_open_files_dormant_rename(workspace, database):
    path = workspace / "original.log"
    renamed = workspace / "renamed.log"
    path.write_text("original\n", encoding="utf-8")
    service = budget_service(workspace, 1)
    if not database:
        config = Path(service.config_file)
        config.write_text("\n".join(line for line in config.read_text().splitlines()
                                     if not line.strip().startswith("db")) + "\n")
    try:
        service.start()
        service.wait_for_records(1)
        wait_for_dormant(service, path)
        path.rename(renamed)
        write_and_sync(renamed, "appended\n")
        records = service.wait_for_records(2, timeout=30)
        service.assert_no_new_records_for(2)
        assert_log_set(records, ["original", "appended"])
    finally:
        service.stop()


@pytest.mark.parametrize("mode", ["gzip", "docker_mode", "multiline"])
def test_max_open_files_preserves_stateful_files(workspace, mode):
    import gzip
    import json

    template = Path(__file__).parent.parent / f"config/tail_{mode}.yaml"
    config = template.read_text().replace("      tag: tail.integration",
                                         "      max_open_files: 1\n      tag: tail.integration")
    config_path = workspace / "stateful.yaml"
    config_path.write_text(config)
    service = Service(config_path, tail_path=workspace / "*.log*", db_path=workspace / "tail.db")
    if mode == "gzip":
        with gzip.open(workspace / "0.log.gz", "wt") as stream:
            stream.write("first\n")
    elif mode == "docker_mode":
        record = {"log": "first\n", "stream": "stdout", "time": "2025-06-16T20:42:22.291Z"}
        (workspace / "0.log").write_text(json.dumps(record) + "\n")
    else:
        (workspace / "0.log").write_text("[2025-06-16 20:42:22,291] INFO first\n")
    (workspace / "1.log").write_text("deferred\n")
    try:
        service.start()
        service.wait_for_records(1, timeout=30)
        service.assert_no_new_records_for(1)
        log = Path(service.flb.log_file).read_text()
        assert "releasing dormant file" not in log
        assert "max_open_files=1 reached; deferring" in log
    finally:
        service.stop()
