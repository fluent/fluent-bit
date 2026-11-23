"""Transient inflater allocation failures must remain retryable."""

import gzip
import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from utils.http_matrix import run_curl_request
from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module")
def allocation_preload(tmp_path_factory):
    """Build a one-shot glibc allocator fault injector for the server process."""
    if platform.system() != "Linux" or platform.libc_ver()[0] != "glibc":
        pytest.skip("allocation interposition requires Linux glibc")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("allocation interposition requires a C compiler")
    source = Path(__file__).with_name("inflation_alloc_failure.c")
    library = tmp_path_factory.mktemp("inflation-allocator") / "allocator.so"
    subprocess.run([compiler, "-shared", "-fPIC", str(source), "-o", str(library)], check=True)
    return library


@pytest.mark.parametrize("allocation", ["input", "output"])
@pytest.mark.parametrize("http_mode", ["http1.1", "http2-prior-knowledge"])
def test_http_inflation_allocation_failure(tmp_path, allocation_preload, allocation, http_mode):
    """Return 503 once, then accept the same compressed request after recovery."""
    body = gzip.compress(b'{"message":"' + b"x" * 32768 + b'"}')
    marker = tmp_path / "fail-next-allocation"
    environment = {
        "LD_PRELOAD": str(allocation_preload),
        # Instrument libc allocations without replacing the fault injector itself.
        "VALGRIND_OPTS": "--soname-synonyms=somalloc=libc.so.6",
        "INFLATION_FAILURE_MARKER": str(marker),
    }
    if allocation == "input":
        environment["INFLATION_CALLOC_SIZE"] = str(len(body))
    else:
        # CFL SDS stores two uint64_t fields and a trailing NUL outside its capacity.
        environment["INFLATION_REALLOC_SIZE"] = str(16384 + 16 + 1)
    config = tmp_path / "http.yaml"
    config.write_text(json.dumps({
        "service": {"flush": 0.1, "grace": 1, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "http", "listen": "127.0.0.1", "http2": "on",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}],
            "outputs": [{"name": "null", "match": "*"}],
        },
    }))
    service = FluentBitTestService(str(config), extra_env=environment)
    try:
        service.start()
        marker.touch()
        for status in (503, 201):
            result = run_curl_request(
                f"http://localhost:{service.flb_listener_port}/", body,
                headers=["Content-Type: application/json", "Content-Encoding: gzip"],
                http_mode=http_mode,
            )
            assert result["status_code"] == status
            assert not marker.exists(), "the intended allocation failure was not injected"
    finally:
        service.stop()
