from pathlib import Path

import pytest
import requests

from server.http_server import data_storage, http_server_run
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, *, config_name="filter_multiline_shutdown.yaml",
                 service_flush="0.2", emitter_mem_buf_limit="10M"):
        config_file = (
            Path(__file__).resolve().parents[1]
            / "config"
            / config_name
        )
        self.service = FluentBitTestService(
            str(config_file),
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "MULTILINE_SERVICE_FLUSH": service_flush,
                "MULTILINE_EMITTER_MEM_BUF_LIMIT": emitter_mem_buf_limit,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )
        self.flb = None
        self.listener_port = None

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
        self.listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def send(self, log, **fields):
        payload = {"log": log}
        payload.update(fields)
        response = requests.post(
            f"http://127.0.0.1:{self.listener_port}/",
            json=payload,
            timeout=10,
        )
        assert response.status_code == 201

    def wait_for_records(self, minimum_count, timeout=20):
        return self.service.wait_for_condition(
            lambda: flattened_records()
            if len(flattened_records()) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.2,
            description=f"{minimum_count} multiline records",
        )

    def wait_for_log(self, text, timeout=20):
        def log_contains_text():
            if not self.flb or not self.flb.log_file:
                return None

            try:
                log_text = Path(self.flb.log_file).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                return None

            return log_text if text in log_text else None

        return self.service.wait_for_condition(
            log_contains_text,
            timeout=timeout,
            interval=0.2,
            description=f"log text {text!r}",
        )


def flattened_records():
    records = []

    for payload in data_storage["payloads"]:
        if isinstance(payload, list):
            records.extend(payload)
        elif payload is not None:
            records.append(payload)

    return records


@pytest.mark.parametrize(
    "pause_before_shutdown",
    [False, True],
    ids=["pending", "emitter-prepaused"],
)
def test_filter_multiline_flushes_pending_group_on_shutdown(pause_before_shutdown):
    padding = "x" * 2048 if pause_before_shutdown else ""
    service = Service(
        service_flush="60" if pause_before_shutdown else "0.2",
        emitter_mem_buf_limit="1K" if pause_before_shutdown else "10M",
    )

    try:
        service.start()
        service.send(
            "Exception in thread main java.lang.IllegalStateException: "
            f"first-complete-marker{padding}"
        )
        service.send("    at com.example.first-stack-frame(First.java:1)")
        service.send(
            "Exception in thread main java.lang.RuntimeException: "
            "dangling-shutdown-marker"
        )

        if pause_before_shutdown:
            service.wait_for_log("emitter_for_multiline.0 paused (mem buf overlimit")
        else:
            service.wait_for_records(1)
    finally:
        service.stop()

    records = flattened_records()
    matching_logs = [
        record["log"]
        for record in records
        if "first-complete-marker" in record.get("log", "")
        or "dangling-shutdown-marker" in record.get("log", "")
    ]

    assert len(matching_logs) == 2

    complete = next(log for log in matching_logs if "first-complete-marker" in log)
    dangling = next(log for log in matching_logs if "dangling-shutdown-marker" in log)

    assert "first-stack-frame" in complete
    assert "dangling-shutdown-marker" not in complete
    assert "first-complete-marker" not in dangling
    assert "first-stack-frame" not in dangling


def test_filter_multiline_flushes_pending_partial_message_on_shutdown():
    service = Service(config_name="filter_multiline_partial_shutdown.yaml")

    try:
        service.start()
        service.send(
            "partial-shutdown-one..",
            partial_message="true",
            partial_id="shutdown",
            partial_ordinal="1",
            partial_last="false",
        )
        service.send(
            "two",
            partial_message="true",
            partial_id="shutdown",
            partial_ordinal="2",
            partial_last="false",
        )
        service.send("partial-shutdown-barrier")

        records = service.wait_for_records(1)
        assert len(records) == 1
        assert records[0]["log"] == "partial-shutdown-barrier"
    finally:
        service.stop()

    records = flattened_records()
    matching_logs = [
        record["log"]
        for record in records
        if record.get("log", "").startswith("partial-shutdown-")
    ]

    assert sorted(matching_logs) == [
        "partial-shutdown-barrier",
        "partial-shutdown-one..two",
    ]
