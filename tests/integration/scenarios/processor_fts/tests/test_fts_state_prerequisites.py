"""ABI regression and lifecycle experiments preceding native state."""
import re
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from test_fts_recipe_preflight import dry_run, preflight_config
from test_fts_records import rows, log_text
from utils.test_service import FluentBitTestService

ROOT = Path(__file__).resolve().parents[5]


@pytest.fixture(scope="module", params=[False, True, "stop", "both", "unflagged"],
                ids=["legacy-descriptor", "preflight-descriptor", "stop-descriptor", "both-descriptor", "unflagged-descriptor"])
def processor_dso(request, tmp_path_factory):
    target = compile_probe(tmp_path_factory, "legacy", request.param)
    return target, request.param


def compile_probe(tmp_path_factory, name, extended=False):
    if sys.platform != "linux":
        pytest.skip("DSO ABI fixture currently uses the Linux .so loader")
    compiler = shutil.which("cc")
    binary = Path(os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))).resolve()
    build = Path(os.environ.get("FTS_BUILD_DIR", str(binary.parent.parent)))
    flags_path = build / "plugins/processor_fts/CMakeFiles/flb-plugin-processor_fts.dir/flags.make"
    if not compiler or not flags_path.exists():
        pytest.skip("DSO ABI fixture needs cc and configured Makefile build include paths")
    flags = flags_path.read_text()
    arguments = []
    for flag_name in ("C_DEFINES", "C_INCLUDES"):
        arguments += shlex.split(re.search(rf"^{flag_name} = (.*)$", flags, re.M).group(1))
    target = tmp_path_factory.mktemp("processor-dso") / f"flb-processor_{name}_probe.so"
    definitions = {
        False: [], True: ["-DPROBE_PREFLIGHT"], "stop": ["-DPROBE_STOP"],
        "both": ["-DPROBE_PREFLIGHT", "-DPROBE_STOP"], "unflagged": ["-DPROBE_UNFLAGGED"],
        "windows": ["-DPROBE_WINDOWS"],
    }[extended]
    subprocess.run([compiler, "-shared", "-fPIC", "-std=gnu11", *arguments,
        *definitions,
        "-o", str(target), str(Path(__file__).with_name(f"{name}_processor.c"))], check=True)
    return target


@pytest.mark.parametrize("placement", ["input", "output"])
def test_dso_old_and_extended_descriptors(tmp_path, processor_dso, placement):
    library, extended = processor_dso
    config = preflight_config(tmp_path, {"name": "legacy_probe", "marker": "ok"}, "logs", placement, 24567)
    data = yaml.safe_load(config.read_text())
    data["plugins"] = [str(library)]
    source = data["pipeline"]["inputs"][0]
    source.update(name="dummy", dummy='{"message":"legacy"}', samples=1)
    source.pop("port")
    config.write_text(yaml.safe_dump(data))
    status, text = dry_run(config, tmp_path)
    assert status == 0, text
    assert "legacy_dso_initialized" not in text
    assert ("new_dso_preflight" in text) == (extended is True or extended == "both")
    data["service"].update(flush=0.2, http_server=True,
                           http_port="${FLUENT_BIT_HTTP_MONITORING_PORT}")
    config.write_text(yaml.safe_dump(data))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        actual = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert actual[0]["message"] == "legacy"
        assert "legacy_dso_initialized" in log_text(service, "legacy_dso_initialized")
    finally:
        service.stop()
    assert log_text(service).count("new_dso_input_stop") == (1 if extended in ("stop", "both") and placement == "input" else 0)


@pytest.fixture(scope="module")
def lifecycle_dso(tmp_path_factory):
    return compile_probe(tmp_path_factory, "lifecycle")


@pytest.mark.parametrize("threaded", [False, True])
def test_timer_thread_and_shutdown_gate(tmp_path, lifecycle_dso, threaded):
    config = tmp_path / "lifecycle.yaml"
    config.write_text(yaml.safe_dump({
        "plugins": [str(lifecycle_dso)],
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "dummy": '{"message":"probe"}',
                        "samples": 2, "threaded": threaded,
                        "processors": {"logs": [{"name": "lifecycle_probe"}]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(lambda: rows(service) and "lifecycle_tick" in log_text(service) and
            "lifecycle_processed count=2" in log_text(service), timeout=30)
    finally:
        service.stop()
    text = log_text(service)
    ticks = re.findall(r"lifecycle_tick same_process=(\d) same_init=(\d)", text)
    assert ticks, text
    assert set(ticks) == {("1", "1")}, text
    assert "lifecycle_exit outputs_empty=1 storage_null=1 processed=2" in text, text
    assert "lifecycle_release status=0" in text, text
    assert "lifecycle_discard held=1 released=1" in text, text
    assert len(rows(service)) == 1, text


def test_output_retry_reexecutes_callback(tmp_path):
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    attempts = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            attempts.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(503 if len(attempts) == 1 else 200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = tmp_path / "retry.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "scheduler.base": 1, "scheduler.cap": 1,
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "dummy": '{"message":"retry"}', "samples": 1}],
            "outputs": [{"name": "http", "match": "*", "host": "127.0.0.1",
                         "port": server.server_port, "format": "json", "retry_limit": False,
                         "workers": 1, "processors": {"logs": [{"name": "fts", "code":
                             'local n = 0; function process(log) n = n + 1; log.body:set("attempt", n) end'}]}}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(lambda: len(attempts) >= 2, timeout=30)
        assert [batch[0]["attempt"] for batch in attempts[:2]] == [1, 2], attempts
    finally:
        service.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
