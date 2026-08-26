import mmap
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
SEED_CONFIG = CONFIG_DIR / "seed_unroutable_chunk.yaml"
RELOAD_WITHOUT_ROUTE = CONFIG_DIR / "reload_without_stale_route.yaml"
RELOAD_WITH_ROUTE = CONFIG_DIR / "reload_with_stale_route.yaml"
RELOAD_WITH_EVICTION = CONFIG_DIR / "reload_with_storage_limit_eviction.yaml"
KEEP_ON_DISK_MESSAGE = "no matching route for dummy.0/"
REGISTER_MESSAGE = "register dummy.0/"
QUEUE_MESSAGE = "queueing dummy.0:"
EVICTION_MESSAGE = (
    "evicted from output queue to make room under "
    "storage.total_limit_size: input=dummy.0 > output=http.0"
)


def wait_for_persisted_chunk(storage_path, process, log_path, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        chunks = list(storage_path.glob("*/*.flb"))
        if chunks and chunks[0].stat().st_size > 0:
            return chunks[0]

        return_code = process.poll()
        if return_code is not None:
            if log_path.exists():
                log = log_path.read_text(encoding="utf-8", errors="replace")
            else:
                log = "seed log was not created"
            raise RuntimeError(
                f"seed Fluent Bit exited with code {return_code} before persisting a chunk:\n{log}"
            )

        time.sleep(0.1)

    raise TimeoutError("timed out waiting for the seed filesystem chunk")


def wait_for_log_occurrences(log_path, text, expected, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if log_path.exists():
            log = log_path.read_text(encoding="utf-8", errors="replace")
            if log.count(text) >= expected:
                return

        time.sleep(0.1)

    raise TimeoutError(f"timed out waiting for {expected} occurrences of {text!r}")


def wait_for_path_removal(path, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not path.exists():
            return

        time.sleep(0.1)

    raise TimeoutError(f"timed out waiting for {path} to be removed")


def seed_persisted_chunk(storage_path, seed_log_path):
    binary_path = FluentBitManager(str(SEED_CONFIG)).binary_absolute_path
    seed_process = subprocess.Popen(
        [binary_path, "-c", str(SEED_CONFIG), "-l", str(seed_log_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        env=os.environ.copy(),
    )

    try:
        return wait_for_persisted_chunk(storage_path, seed_process, seed_log_path)
    finally:
        if seed_process.poll() is None:
            seed_process.kill()
        seed_process.wait(timeout=10)


@pytest.fixture
def seeded_chunk(tmp_path, monkeypatch):
    storage_path = tmp_path / "storage"
    storage_path.mkdir()
    seed_log_path = tmp_path / "seed.log"
    missing_path = tmp_path / "does-not-exist.log"
    live_one_path = tmp_path / "live-one.log"
    live_two_path = tmp_path / "live-two.log"

    monkeypatch.setenv("STORAGE_BACKLOG_PATH", str(storage_path))
    monkeypatch.setenv("STORAGE_BACKLOG_MISSING_PATH", str(missing_path))
    monkeypatch.setenv("STORAGE_BACKLOG_LIVE_ONE_PATH", str(live_one_path))
    monkeypatch.setenv("STORAGE_BACKLOG_LIVE_TWO_PATH", str(live_two_path))
    monkeypatch.setenv("STORAGE_BACKLOG_TOTAL_LIMIT_SIZE", str(mmap.PAGESIZE * 2))

    persisted_chunk = seed_persisted_chunk(storage_path, seed_log_path)
    assert persisted_chunk.exists()

    return persisted_chunk


def test_routable_persisted_chunk_is_replayed_on_startup(seeded_chunk):
    manager = FluentBitManager(str(RELOAD_WITH_ROUTE))

    try:
        manager.start()
        wait_for_log_occurrences(
            Path(manager.log_file), REGISTER_MESSAGE, expected=1
        )
        wait_for_log_occurrences(
            Path(manager.log_file), QUEUE_MESSAGE, expected=1
        )
        wait_for_path_removal(seeded_chunk)
    finally:
        manager.stop()

    assert not seeded_chunk.exists()


def test_loaded_backlog_eviction_reports_original_input(seeded_chunk):
    manager = FluentBitManager(str(RELOAD_WITH_EVICTION))
    live_one_path = Path(os.environ["STORAGE_BACKLOG_LIVE_ONE_PATH"])
    live_two_path = Path(os.environ["STORAGE_BACKLOG_LIVE_TWO_PATH"])

    try:
        manager.start()
        wait_for_log_occurrences(
            Path(manager.log_file), QUEUE_MESSAGE, expected=1
        )

        live_one_path.write_text("live one\n", encoding="utf-8")
        live_two_path.write_text("live two\n", encoding="utf-8")

        wait_for_log_occurrences(
            Path(manager.log_file), EVICTION_MESSAGE, expected=1
        )
        wait_for_path_removal(seeded_chunk)

        log = Path(manager.log_file).read_text(encoding="utf-8", errors="replace")
    finally:
        manager.stop()

    assert "input=storage_backlog." not in log
    assert not seeded_chunk.exists()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="SIGHUP is unavailable")
def test_unroutable_chunk_stays_on_disk_across_hot_reload(seeded_chunk):
    manager = FluentBitManager(str(RELOAD_WITHOUT_ROUTE))

    try:
        manager.start()
        wait_for_log_occurrences(
            Path(manager.log_file), KEEP_ON_DISK_MESSAGE, expected=1
        )
        assert seeded_chunk.exists()

        manager.send_sighup()
        manager.wait_for_hot_reload_count(1, timeout=20)
        wait_for_log_occurrences(
            Path(manager.log_file), KEEP_ON_DISK_MESSAGE, expected=2, timeout=20
        )
        assert seeded_chunk.exists()
    finally:
        manager.stop()

    assert seeded_chunk.exists()


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="SIGHUP is unavailable")
def test_restored_route_recovers_chunk_during_hot_reload(tmp_path, seeded_chunk):
    runtime_config = tmp_path / "fluent-bit.yaml"
    shutil.copyfile(RELOAD_WITHOUT_ROUTE, runtime_config)
    manager = FluentBitManager(str(runtime_config))

    try:
        manager.start()
        wait_for_log_occurrences(
            Path(manager.log_file), KEEP_ON_DISK_MESSAGE, expected=1
        )
        assert seeded_chunk.exists()

        pending_config = tmp_path / "fluent-bit.yaml.tmp"
        shutil.copyfile(RELOAD_WITH_ROUTE, pending_config)
        os.replace(pending_config, runtime_config)

        manager.send_sighup()
        manager.wait_for_hot_reload_count(1, timeout=20)
        wait_for_log_occurrences(
            Path(manager.log_file), REGISTER_MESSAGE, expected=1, timeout=20
        )
        wait_for_log_occurrences(
            Path(manager.log_file), QUEUE_MESSAGE, expected=1, timeout=20
        )
        wait_for_path_removal(seeded_chunk, timeout=20)
    finally:
        manager.stop()

    assert not seeded_chunk.exists()
