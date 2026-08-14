import json
import os
from pathlib import Path
import tempfile

import requests

from server.http_server import data_storage, http_server_run
from utils.memory_check import memory_check_enabled
from utils.test_service import FluentBitTestService


MESSAGE_SIZE = 40 * 1024
RECORD_COUNT = 200


def create_message(sequence):
    prefix = f"<TEST {'®' * ((sequence % 15) + 1)}>"
    suffix = "</TEST>"
    token = f"{sequence},"
    remaining = MESSAGE_SIZE - len(prefix.encode("utf-8")) - len(suffix)
    repetitions = remaining // len(token)
    padding = remaining - repetitions * len(token)

    return prefix + token * repetitions + "-" * padding + suffix


def write_input(path):
    expected_messages = []

    with path.open("w", encoding="utf-8") as input_file:
        for sequence in range(RECORD_COUNT):
            message = create_message(sequence)
            expected_messages.append(message)
            json.dump({"seq": sequence, "msg": message}, input_file, ensure_ascii=False)
            input_file.write("\n")

    return expected_messages


def count_loki_values():
    count = 0

    for payload in data_storage["payloads"]:
        if not isinstance(payload, dict):
            continue

        for stream in payload.get("streams", []):
            count += len(stream.get("values", []))

    return count


def collect_loki_records():
    records = []

    for payload in data_storage["payloads"]:
        assert isinstance(payload, dict)

        for stream in payload.get("streams", []):
            for value in stream.get("values", []):
                records.append(json.loads(value[1]))

    return records


class Service:
    def __init__(self, input_path):
        test_directory = Path(__file__).resolve().parent
        config_directory = test_directory.parent / "config"
        self.service = FluentBitTestService(
            str(config_directory / "out_loki_long_unicode.yaml"),
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "LOKI_INPUT_PATH": str(input_path),
                "LOKI_PARSERS_FILE": str(config_directory / "parsers.conf"),
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

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

    def stop(self):
        self.service.stop()

    def wait_for_records(self):
        timeout = 60 if memory_check_enabled() else 20

        self.service.wait_for_condition(
            lambda: count_loki_values() >= RECORD_COUNT,
            timeout=timeout,
            interval=0.5,
            description=f"{RECORD_COUNT} Loki values",
        )


def test_out_loki_preserves_long_unicode_json_strings():
    with tempfile.TemporaryDirectory(prefix="flb-out-loki-it-") as temp_directory:
        input_path = Path(temp_directory) / "input.log"
        expected_messages = write_input(input_path)
        service = Service(input_path)

        try:
            service.start()
            service.wait_for_records()
        finally:
            service.stop()

        records = collect_loki_records()

    assert len(records) == RECORD_COUNT
    assert all(set(record) == {"msg"} for record in records)
    assert sorted(record["msg"] for record in records) == sorted(expected_messages)
