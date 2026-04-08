import json
import logging
import os

from server.chunked_http_server import (
    chunked_http_server_run,
    chunked_response_storage,
    configure_chunked_http_response,
    shutdown_chunked_http_server,
)
from utils.test_service import FluentBitTestService


logger = logging.getLogger(__name__)


class Service:
    def __init__(self, config_file, *, response_setup=None):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.response_setup = response_setup
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=chunked_response_storage,
            data_keys=["payloads", "requests"],
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        chunked_http_server_run(service.test_suite_http_port)
        if self.response_setup is not None:
            self.response_setup()
        self.service.wait_for_http_endpoint(
            f"http://127.0.0.1:{service.test_suite_http_port}/ping",
            timeout=10,
            interval=0.5,
        )

    def _stop_receiver(self, service):
        shutdown_chunked_http_server()

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: chunked_response_storage["requests"]
            if len(chunked_response_storage["requests"]) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} outbound HTTP requests",
        )

    def wait_for_log_message(self, pattern, timeout=10):
        def _read_log():
            if not os.path.exists(self.flb.log_file):
                return None

            with open(self.flb.log_file, encoding="utf-8", errors="replace") as log_file:
                contents = log_file.read()

            if pattern in contents:
                return contents

            return None

        return self.service.wait_for_condition(
            _read_log,
            timeout=timeout,
            interval=0.25,
            description=f"log message '{pattern}'",
        )


def _assert_payload(request_record):
    assert request_record["path"] == "/data"
    assert request_record["method"] == "POST"
    assert "application/json" in request_record["headers"].get("Content-Type", "")

    payload = json.loads(request_record["raw_data"])
    assert isinstance(payload, list)
    assert payload[0]["message"] in {
        "hello from chunked out_http",
        "retry chunked response",
    }
    assert payload[0]["source"] == "dummy"


def test_out_http_accepts_basic_chunked_response():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            fragments=[
                "2\r\nOK\r\n",
                "0\r\n\r\n",
            ]
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_accepts_chunked_response_with_trailers_and_extensions():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            headers=[
                ("Transfer-Encoding", "chunked"),
                ("Trailer", "Expires, X-Trace"),
                ("Connection", "close"),
            ],
            fragments=[
                "4;foo=bar\r\nWiki\r\n",
                "5\r\npedia\r\n",
                "0;done=yes\r\nExpires: tomorrow\r\nX-Trace: abc\r\n\r\n",
            ],
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_accepts_fragmented_chunked_terminal_sequence():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            headers=[
                ("Transfer-Encoding", "chunked"),
                ("Trailer", "X-Trace"),
                ("Connection", "close"),
            ],
            fragments=[
                "4\r\nWi",
                "ki\r\n",
                "5\r\npedia\r\n",
                "0\r\n",
                "X-Trace: stream\r\n",
                "\r\n",
            ],
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_retries_when_chunked_trailer_block_is_invalid():
    service = Service(
        "out_http_chunked_retry.yaml",
        response_setup=lambda: configure_chunked_http_response(
            fragments=[
                "4\r\nWiki\r\n",
                "0\r\nBroken-Trailer\r\n\r\n",
            ]
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    service.stop()

    assert len(requests_seen) >= 2
    _assert_payload(requests_seen[0])


def test_out_http_accepts_uppercase_hex_and_whitespace_chunk_size():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            fragments=[
                " 2 ;foo=bar\r\nOK\r\n",
                "0\r\n\r\n",
            ]
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_accepts_empty_terminal_chunk_split_from_final_crlf():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            fragments=[
                "2\r\nOK\r\n",
                "0\r\n",
                "\r\n",
            ]
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_accepts_multi_stage_trailer_delivery():
    service = Service(
        "out_http_chunked_basic.yaml",
        response_setup=lambda: configure_chunked_http_response(
            headers=[
                ("Transfer-Encoding", "chunked"),
                ("Trailer", "X-One, X-Two"),
                ("Connection", "close"),
            ],
            fragments=[
                "2\r\nOK\r\n",
                "0\r\n",
                "X-One: 1\r\n",
                "X-Two: 2\r\n",
                "\r\n",
            ],
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(1)
    service.stop()

    assert len(requests_seen) == 1
    _assert_payload(requests_seen[0])


def test_out_http_response_timeout_retries_hung_server():
    service = Service(
        "out_http_chunked_response_timeout.yaml",
        response_setup=lambda: configure_chunked_http_response(
            hang_before_headers=True,
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("response timeout reached", timeout=15)
    service.stop()

    assert len(requests_seen) >= 2
    assert "response timeout reached" in log_text
    _assert_payload(requests_seen[0])


def test_out_http_read_idle_timeout_retries_stalled_chunked_response():
    service = Service(
        "out_http_chunked_read_idle_timeout.yaml",
        response_setup=lambda: configure_chunked_http_response(
            headers=[
                ("Transfer-Encoding", "chunked"),
                ("Connection", "close"),
            ],
            fragments=[
                "4\r\nWiki\r\n",
            ],
            hang_after_fragment_index=0,
        ),
    )
    service.start()

    requests_seen = service.wait_for_requests(2, timeout=15)
    log_text = service.wait_for_log_message("read idle timeout reached", timeout=15)
    service.stop()

    assert len(requests_seen) >= 2
    assert "read idle timeout reached" in log_text
    _assert_payload(requests_seen[0])
