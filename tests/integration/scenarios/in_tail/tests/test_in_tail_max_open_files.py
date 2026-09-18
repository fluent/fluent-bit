"""The shared open-file budget must survive EOF and release on removal."""
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


@pytest.mark.parametrize("limit", [None, 0, 1, 2])
def test_max_open_files_deferred_until_removal(workspace, limit):
    for index in range(3):
        (workspace / f"{index}.log").write_text(f"initial-{index}\n", encoding="utf-8")
    service = budget_service(workspace, limit)
    admitted = limit or 3

    try:
        service.start()
        records = service.wait_for_records(admitted)
        service.assert_no_new_records_for(admitted)
        paths = {Path(record["file"]) for record in records}
        assert len(paths) == admitted

        # EOF and promotion to event monitoring must retain the reservation.
        for path in paths:
            write_and_sync(path, f"append-{path.stem}\n")
        records = service.wait_for_records(admitted * 2)
        service.assert_no_new_records_for(admitted * 2)

        # Retiring admitted files allows discovery to retry the deferred files.
        for path in paths:
            path.rename(path.with_suffix(".retired"))
        if admitted < 3:
            records = service.wait_for_records(admitted * 2 + min(admitted, 3 - admitted), timeout=30)
            if admitted == 1:
                second_path = Path(records[-1]["file"])
                second_path.rename(second_path.with_suffix(".retired"))
                records = service.wait_for_records(4, timeout=30)
        assert_log_set(records, [f"initial-{i}" for i in range(3)] +
                       [f"append-{path.stem}" for path in paths])
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
            (workspace / f"{index}.log").write_text(f"line-{index}\n", encoding="utf-8")
        service.wait_for_records(2)
        assert warning not in log_text()

        (workspace / "2.log").write_text("line-2\n", encoding="utf-8")
        service.wait_for_records(3)
        assert log_text().count(warning) == 1

        (workspace / "3.log").write_text("line-3\n", encoding="utf-8")
        service.wait_for_records(4)
        assert log_text().count(warning) == 1

        (workspace / "4.log").write_text("line-4\n", encoding="utf-8")
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
            (workspace / f"new-{index}.log").write_text(f"new-{index}\n", encoding="utf-8")
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
        for total in (2, 4, 6, 8):
            records = service.wait_for_records(total, timeout=30)
            service.assert_no_new_records_for(total)
            assert len(records) == total
            for record in records[-2:]:
                path = Path(record["file"])
                path.rename(path.with_suffix(".retired"))
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
        records = second.wait_for_records(1)
        second.assert_no_new_records_for(1)
        admitted = Path(records[0]["file"])
        admitted.rename(admitted.with_suffix(".retired"))
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
        active.write_text("active\n", encoding="utf-8")
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
