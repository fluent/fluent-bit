import pytest
import os
import base64
import json
import threading
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from utils.data_utils import read_file
from utils.filesystem import make_link
from utils.network import find_available_port, wait_for_port_to_be_free
from utils.test_service import FluentBitTestService


FLEET_ID = "test-fleet"
PROJECT_ID = "test-project"
MACHINE_ID = "test-machine"
PARSER_FILE = "parser--linux.yaml"
LAST_MODIFIED = "Thu, 18 Jun 2026 17:00:00 GMT"
API_KEY = (
    base64.b64encode(json.dumps({"ProjectID": PROJECT_ID}).encode("utf-8"))
    .decode("ascii")
    .rstrip("=")
    + ".signature"
)

PARSER_CONFIG = """
parsers:
  - name: fleet_json
    format: json
""".lstrip()


class FleetAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        self.server.requests.append(
            {
                "path": parsed.path,
                "query": parsed.query,
                "headers": dict(self.headers),
            }
        )

        if parsed.path == "/v1/search":
            self._send_response(
                200,
                json.dumps([{"id": FLEET_ID}]),
                "application/json",
            )
            return

        if parsed.path == f"/v1/fleets/{FLEET_ID}/config":
            self._send_response(
                200,
                self.server.fleet_config,
                "application/x-yaml",
                {"Last-modified": self.server.last_modified},
            )
            return

        if parsed.path == f"/v1/fleets/{FLEET_ID}/files":
            if self.server.file_failures > 0:
                self.server.file_failures -= 1
                self._send_response(503, "temporary failure", "text/plain")
                return
            self._send_response(
                200,
                json.dumps(self.server.fleet_files),
                "application/json",
            )
            return

        self._send_response(404, "not found", "text/plain")

    def log_message(self, format, *args):
        return

    def _send_response(self, status, body, content_type, extra_headers=None):
        body_bytes = body.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))

        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body_bytes)


class FleetAPIServer:
    def __init__(self, port, fleet_config, fleet_files=None):
        self.port = port
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), FleetAPIHandler)
        self.httpd.fleet_config = fleet_config
        self.httpd.fleet_files = fleet_files or []
        self.httpd.last_modified = LAST_MODIFIED
        self.httpd.requests = []
        self.httpd.file_failures = 0
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        wait_for_port_to_be_free(self.port, timeout=5)

    @property
    def requests(self):
        return self.httpd.requests


def _yaml_string(value):
    return json.dumps(str(value))


def _fleet_base_dir(cache_dir):
    return Path(cache_dir) / MACHINE_ID / FLEET_ID


def _fleet_files_payload():
    encoded = base64.b64encode(PARSER_CONFIG.encode("utf-8")).decode("ascii")
    return [{"name": PARSER_FILE, "contents": encoded}]


def _customs_section(cache_dir, api_port, *, legacy=False, interval_sec="3600"):
    legacy_value = "on" if legacy else "off"

    return f"""
customs:
  - name: calyptia
    api_key: {API_KEY}
    calyptia_host: 127.0.0.1
    calyptia_port: "{api_port}"
    calyptia_tls: off
    calyptia_tls.verify: off
    fleet_name: {FLEET_ID}
    machine_id: {MACHINE_ID}
    fleet.config_dir: {_yaml_string(cache_dir)}
    fleet_config_legacy_format: {legacy_value}
    fleet.interval_sec: "{interval_sec}"
    fleet.interval_nsec: "0"
""".lstrip()


def _bootstrap_config(cache_dir, api_port, *, legacy=False, interval_sec="3600"):
    return f"""
service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

""".lstrip() + _customs_section(
        cache_dir, api_port, legacy=legacy, interval_sec=interval_sec
    )


def _custom_config(cache_dir, api_port, *, legacy=False, interval_sec="3600"):
    return _customs_section(cache_dir, api_port, legacy=legacy, interval_sec=interval_sec)


def _fleet_config(
    cache_dir,
    api_port,
    marker,
    *,
    include_custom=False,
    include_path=PARSER_FILE,
    interval_sec="3600",
):
    custom = (
        _custom_config(cache_dir, api_port, interval_sec=interval_sec) + "\n"
        if include_custom else ""
    )

    return f"""
{custom}
service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

includes:
  - {_yaml_string(include_path)}

pipeline:
  inputs:
    - name: dummy
      tag: fleet.test
      dummy: '{{"message":"{marker}"}}'
      samples: 1
      rate: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
""".lstrip()


def _legacy_fleet_config(marker):
    dummy = json.dumps({"message": marker})

    return f"""
[INPUT]
    Name dummy
    Tag fleet.test
    Dummy {dummy}
    Samples 1
    Rate 1

[OUTPUT]
    Name stdout
    Match *
    Format json_lines
""".lstrip()


def _write_bootstrap_config(tmp_path, cache_dir, api_port, *, legacy=False, interval_sec="3600"):
    config_path = tmp_path / "bootstrap.yaml"
    config_path.write_text(
        _bootstrap_config(cache_dir, api_port, legacy=legacy, interval_sec=interval_sec),
        encoding="utf-8",
    )
    return config_path


def _write_old_cache(
    cache_dir,
    api_port,
    ref_name,
    marker,
    *,
    target_marker=None,
    interval_sec="3600",
):
    timestamp = 1234567890
    base_dir = _fleet_base_dir(cache_dir)
    timestamp_dir = base_dir / str(timestamp)
    flat_config = base_dir / f"{timestamp}.yaml"
    nested_config = timestamp_dir / "config.yaml"
    parser_config = timestamp_dir / PARSER_FILE

    timestamp_dir.mkdir(parents=True)
    flat_config.write_text(
        _fleet_config(
            cache_dir,
            api_port,
            marker,
            include_custom=True,
            interval_sec=interval_sec,
        ),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")

    if target_marker is not None:
        nested_config.write_text(
            _fleet_config(
                cache_dir,
                api_port,
                target_marker,
                include_custom=True,
                interval_sec=interval_sec,
            ),
            encoding="utf-8",
        )

    (base_dir / f"{ref_name}.ref").write_text(f"{flat_config}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "flat_config": flat_config,
        "nested_config": nested_config,
        "parser_config": parser_config,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _write_nested_cache(cache_dir, api_port, ref_name, marker):
    timestamp = 1234567890
    base_dir = _fleet_base_dir(cache_dir)
    timestamp_dir = base_dir / str(timestamp)
    nested_config = timestamp_dir / "config.yaml"
    parser_config = timestamp_dir / PARSER_FILE

    timestamp_dir.mkdir(parents=True)
    nested_config.write_text(
        _fleet_config(cache_dir, api_port, marker, include_custom=True),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")
    (base_dir / f"{ref_name}.ref").write_text(f"{nested_config}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "nested_config": nested_config,
        "parser_config": parser_config,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _write_base_config_ref(cache_dir, api_port, ref_name, config_name, marker):
    base_dir = _fleet_base_dir(cache_dir)
    config_path = base_dir / config_name
    parser_config = base_dir / PARSER_FILE

    base_dir.mkdir(parents=True)
    config_path.write_text(
        _fleet_config(cache_dir, api_port, marker, include_custom=True),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")
    (base_dir / f"{ref_name}.ref").write_text(f"{config_path}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "config_path": config_path,
        "parser_config": parser_config,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _write_external_config_ref(tmp_path, cache_dir, api_port, ref_name, marker):
    base_dir = _fleet_base_dir(cache_dir)
    external_dir = tmp_path / "external-config"
    config_path = external_dir / "1234567890.yaml"
    parser_config = external_dir / PARSER_FILE

    base_dir.mkdir(parents=True)
    external_dir.mkdir()
    config_path.write_text(
        _fleet_config(cache_dir, api_port, marker, include_custom=True),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")
    (base_dir / f"{ref_name}.ref").write_text(f"{config_path}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "config_path": config_path,
        "parser_config": parser_config,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _write_external_nested_config_ref(
    tmp_path,
    cache_dir,
    api_port,
    ref_name,
    marker,
    *,
    interval_sec="3600",
):
    base_dir = _fleet_base_dir(cache_dir)
    external_dir = tmp_path / "external-config"
    config_path = external_dir / "config.yaml"
    parser_config = external_dir / PARSER_FILE
    sentinel = external_dir / "keep.txt"

    base_dir.mkdir(parents=True)
    external_dir.mkdir()
    config_path.write_text(
        _fleet_config(cache_dir, api_port, marker, include_custom=True, interval_sec=interval_sec),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")
    sentinel.write_text("keep this file\n", encoding="utf-8")
    (base_dir / f"{ref_name}.ref").write_text(f"{config_path}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "config_path": config_path,
        "external_dir": external_dir,
        "parser_config": parser_config,
        "sentinel": sentinel,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _write_blocked_migration_cache(cache_dir, api_port, ref_name, marker):
    timestamp = 1234567890
    base_dir = _fleet_base_dir(cache_dir)
    flat_config = base_dir / f"{timestamp}.yaml"
    timestamp_blocker = base_dir / str(timestamp)
    parser_config = base_dir / PARSER_FILE

    base_dir.mkdir(parents=True)
    flat_config.write_text(
        _fleet_config(cache_dir, api_port, marker, include_custom=True),
        encoding="utf-8",
    )
    parser_config.write_text(PARSER_CONFIG, encoding="utf-8")
    timestamp_blocker.write_text("not a directory\n", encoding="utf-8")
    (base_dir / f"{ref_name}.ref").write_text(f"{flat_config}\n", encoding="utf-8")

    return {
        "base_dir": base_dir,
        "flat_config": flat_config,
        "timestamp_blocker": timestamp_blocker,
        "parser_config": parser_config,
        "ref_file": base_dir / f"{ref_name}.ref",
    }


def _wait_for_log_contains(service, text, timeout=30):
    def _read_matching_log():
        log_text = read_file(service.flb.log_file)
        if text in log_text:
            return log_text
        return None

    return service.wait_for_condition(
        _read_matching_log,
        timeout=timeout,
        interval=0.5,
        description=f"log text {text!r}",
    )


def _assert_no_include_error(log_text):
    assert "yaml error" not in log_text
    assert f"including file '{PARSER_FILE}'" not in log_text


def _run_service(config_path, marker, timeout=30):
    service = FluentBitTestService(str(config_path))

    try:
        service.start()
        log_text = _wait_for_log_contains(service, marker, timeout=timeout)
    finally:
        service.stop()

    _assert_no_include_error(log_text)
    return log_text


def _read_ref_path(ref_file):
    return Path(ref_file.read_text(encoding="utf-8").strip())


def test_fleet_bootstrap_numeric_config_yaml_path_fetches_immediately(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "numeric-bootstrap-path-fetch-ok"
    bootstrap_dir = tmp_path / "2026"
    bootstrap_dir.mkdir()
    config_path = bootstrap_dir / "config.yaml"
    config_path.write_text(_bootstrap_config(cache_dir, api_port), encoding="utf-8")
    fleet_config = _fleet_config(cache_dir, api_port, marker)

    with FleetAPIServer(api_port, fleet_config, _fleet_files_payload()):
        log_text = _run_service(config_path, marker)

    nested_configs = list(_fleet_base_dir(cache_dir).glob("*/config.yaml"))
    assert len(nested_configs) == 1
    assert _read_ref_path(_fleet_base_dir(cache_dir) / "cur.ref") == nested_configs[0]
    assert marker in log_text


def test_fleet_yaml_download_places_config_next_to_fleet_files(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "fresh-fleet-relative-include-ok"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    fleet_config = _fleet_config(cache_dir, api_port, marker)

    with FleetAPIServer(api_port, fleet_config, _fleet_files_payload()) as api:
        log_text = _run_service(config_path, marker)

    nested_configs = list(_fleet_base_dir(cache_dir).glob("*/config.yaml"))
    assert len(nested_configs) == 1
    assert (nested_configs[0].parent / PARSER_FILE).is_file()
    assert _read_ref_path(_fleet_base_dir(cache_dir) / "cur.ref") == nested_configs[0]
    assert any(request["path"] == f"/v1/fleets/{FLEET_ID}/config" for request in api.requests)
    assert any(request["path"] == f"/v1/fleets/{FLEET_ID}/files" for request in api.requests)
    assert marker in log_text


def test_fleet_yaml_download_preserves_absolute_includes(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "fresh-fleet-absolute-include-ok"
    absolute_parser = tmp_path / PARSER_FILE
    absolute_parser.write_text(PARSER_CONFIG, encoding="utf-8")
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    fleet_config = _fleet_config(
        cache_dir,
        api_port,
        marker,
        include_path=absolute_parser,
    )

    with FleetAPIServer(api_port, fleet_config) as api:
        log_text = _run_service(config_path, marker)

    nested_configs = list(_fleet_base_dir(cache_dir).glob("*/config.yaml"))
    assert len(nested_configs) == 1
    assert not (nested_configs[0].parent / PARSER_FILE).exists()
    assert _read_ref_path(_fleet_base_dir(cache_dir) / "cur.ref") == nested_configs[0]
    assert any(request["path"] == f"/v1/fleets/{FLEET_ID}/config" for request in api.requests)
    assert marker in log_text


def test_fleet_legacy_download_keeps_flat_conf_ref(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "legacy-fleet-flat-conf-ok"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port, legacy=True)

    with FleetAPIServer(api_port, _legacy_fleet_config(marker)) as api:
        log_text = _run_service(config_path, marker)

    base_dir = _fleet_base_dir(cache_dir)
    flat_configs = [path for path in base_dir.glob("*.conf") if path.name != "header.conf"]
    assert len(flat_configs) == 1
    assert not list(base_dir.glob("*/config.yaml"))
    assert _read_ref_path(base_dir / "cur.ref") == flat_configs[0]
    assert any(request["query"] == "format=ini&config_format=ini" for request in api.requests)
    assert marker in log_text


def test_fleet_startup_migrates_flat_cur_ref_for_relative_includes(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "cur-ref-migrated-relative-include-ok"
    paths = _write_old_cache(cache_dir, api_port, "cur", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["nested_config"].is_file()
    assert not paths["flat_config"].exists()
    assert _read_ref_path(paths["ref_file"]) == paths["nested_config"]
    assert marker in log_text


def test_fleet_migrates_flat_cache_then_applies_server_update(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    old_marker = "migrated-flat-fleet-config-ok"
    new_marker = "server-updated-nested-fleet-config-ok"
    paths = _write_old_cache(
        cache_dir,
        api_port,
        "cur",
        old_marker,
        interval_sec="2",
    )
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    fleet_config = _fleet_config(cache_dir, api_port, new_marker, interval_sec="1")
    service = FluentBitTestService(str(config_path))

    with FleetAPIServer(api_port, fleet_config, _fleet_files_payload()) as api:
        try:
            service.start()
            _wait_for_log_contains(service, old_marker, timeout=30)
            log_text = _wait_for_log_contains(service, new_marker, timeout=45)
            service.wait_for_condition(
                lambda: (
                    paths["ref_file"].is_file()
                    and _read_ref_path(paths["ref_file"]) != paths["nested_config"]
                    and not (paths["base_dir"] / "old.ref").exists()
                ),
                timeout=45,
                interval=0.5,
                description="updated fleet config commit and old config cleanup",
            )
        finally:
            service.stop()

    current_config = _read_ref_path(paths["ref_file"])
    _assert_no_include_error(log_text)
    assert not paths["flat_config"].exists()
    assert not paths["nested_config"].exists()
    assert current_config.name == "config.yaml"
    assert current_config.parent.parent == paths["base_dir"]
    assert (current_config.parent / PARSER_FILE).is_file()
    assert new_marker in current_config.read_text(encoding="utf-8")
    assert any(request["path"] == f"/v1/fleets/{FLEET_ID}/config" for request in api.requests)
    assert any(request["path"] == f"/v1/fleets/{FLEET_ID}/files" for request in api.requests)
    assert old_marker in log_text
    assert new_marker in log_text


def test_fleet_startup_keeps_nested_cur_ref_for_relative_includes(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "nested-cur-ref-relative-include-ok"
    paths = _write_nested_cache(cache_dir, api_port, "cur", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["nested_config"].is_file()
    assert _read_ref_path(paths["ref_file"]) == paths["nested_config"]
    assert marker in log_text


def test_fleet_startup_migrates_flat_old_ref_fallback(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "old-ref-migrated-relative-include-ok"
    paths = _write_old_cache(cache_dir, api_port, "old", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["nested_config"].is_file()
    assert not (paths["base_dir"] / "cur.ref").exists()
    assert not paths["flat_config"].exists()
    assert _read_ref_path(paths["ref_file"]) == paths["nested_config"]
    assert marker in log_text


def test_fleet_startup_uses_existing_nested_config_when_ref_is_flat(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    flat_marker = "flat-config-should-not-load"
    nested_marker = "existing-nested-config-relative-include-ok"
    paths = _write_old_cache(
        cache_dir,
        api_port,
        "cur",
        flat_marker,
        target_marker=nested_marker,
    )
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, nested_marker)

    assert paths["nested_config"].is_file()
    assert paths["flat_config"].exists()
    assert _read_ref_path(paths["ref_file"]) == paths["nested_config"]
    assert nested_marker in log_text
    assert flat_marker not in log_text


def test_fleet_startup_keeps_external_flat_yaml_ref(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "external-flat-ref-relative-include-ok"
    paths = _write_external_config_ref(tmp_path, cache_dir, api_port, "cur", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["config_path"].is_file()
    assert paths["parser_config"].is_file()
    assert not (paths["base_dir"] / "1234567890" / "config.yaml").exists()
    assert _read_ref_path(paths["ref_file"]) == paths["config_path"]
    assert marker in log_text


def test_fleet_update_keeps_external_config_yaml_parent(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    old_marker = "external-nested-config-initial-ok"
    new_marker = "external-nested-config-update-ok"
    paths = _write_external_nested_config_ref(
        tmp_path,
        cache_dir,
        api_port,
        "cur",
        old_marker,
        interval_sec="1",
    )
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port, interval_sec="1")
    fleet_config = _fleet_config(cache_dir, api_port, new_marker)
    service = FluentBitTestService(str(config_path))

    with FleetAPIServer(api_port, fleet_config, _fleet_files_payload()):
        try:
            service.start()
            log_text = _wait_for_log_contains(service, new_marker, timeout=45)
            service.wait_for_condition(
                lambda: not (paths["base_dir"] / "old.ref").exists(),
                timeout=45,
                interval=0.5,
                description="old fleet ref cleanup",
            )
        finally:
            service.stop()

    _assert_no_include_error(log_text)
    assert paths["external_dir"].is_dir()
    assert paths["sentinel"].is_file()
    assert paths["parser_config"].is_file()
    assert new_marker in log_text


def test_fleet_startup_keeps_non_timestamp_yaml_ref(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "manual-yaml-ref-relative-include-ok"
    paths = _write_base_config_ref(cache_dir, api_port, "cur", "manual.yaml", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["config_path"].is_file()
    assert paths["parser_config"].is_file()
    assert not (paths["base_dir"] / "manual" / "config.yaml").exists()
    assert _read_ref_path(paths["ref_file"]) == paths["config_path"]
    assert marker in log_text


def test_fleet_startup_keeps_flat_ref_when_migration_target_is_blocked(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "blocked-migration-flat-ref-relative-include-ok"
    paths = _write_blocked_migration_cache(cache_dir, api_port, "cur", marker)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)

    log_text = _run_service(config_path, marker)

    assert paths["flat_config"].is_file()
    assert paths["timestamp_blocker"].is_file()
    assert _read_ref_path(paths["ref_file"]) == paths["flat_config"]
    assert marker in log_text


@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
def test_fleet_attachment_symlink_policy(tmp_path, follow_symlinks):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    timestamp = int(parsedate_to_datetime(LAST_MODIFIED).timestamp())
    attachment_dir = _fleet_base_dir(cache_dir) / str(timestamp)
    attachment_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("untouched\n")
    make_link(attachment_dir / PARSER_FILE, victim)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    if follow_symlinks is not None:
        config_path.write_text(config_path.read_text().replace(
            "    fleet.config_dir:",
            f"    fleet.follow_symlinks: {str(follow_symlinks).lower()}\n    fleet.config_dir:",
        ))
    config = _fleet_config(cache_dir, api_port, "symlink-policy-reload")
    with FleetAPIServer(api_port, config, _fleet_files_payload()):
        service = FluentBitTestService(str(config_path), extra_env={"TZ": "UTC"})
        try:
            service.start()
            _wait_for_log_contains(service, "unable to write fleet files safely"
                                   if follow_symlinks is False else "symlink-policy-reload")
        finally:
            service.stop()
    assert victim.read_text() == ("untouched\n" if follow_symlinks is False else PARSER_CONFIG)


def test_fleet_attachment_rejects_parent_traversal(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    config = _fleet_config(cache_dir, api_port, "must-not-reload")
    payload = [{"name": "../escaped", "contents": base64.b64encode(b"escape").decode()}]
    with FleetAPIServer(api_port, config, payload):
        service = FluentBitTestService(str(config_path))
        try:
            service.start()
            _wait_for_log_contains(service, "unable to write fleet files safely")
        finally:
            service.stop()
    assert not (_fleet_base_dir(cache_dir) / "escaped").exists()


def _set_follow_symlinks(config_path, follow_symlinks):
    config_path.write_text(config_path.read_text().replace(
        "    fleet.config_dir:",
        f"    fleet.follow_symlinks: {str(follow_symlinks).lower()}\n    fleet.config_dir:",
    ))


@pytest.mark.parametrize("cached", [False, True], ids=["bootstrap", "update"])
@pytest.mark.parametrize("follow_symlinks", [True, False], ids=["follow", "harden"])
def test_fleet_retries_failed_attachments(tmp_path, cached, follow_symlinks):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "retried-revision-applied"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port, interval_sec="2")
    _set_follow_symlinks(config_path, follow_symlinks)
    victim = tmp_path / "outside" / "keep"
    victim.parent.mkdir()
    victim.write_text("untouched")
    old_directory = None
    if cached:
        paths = _write_nested_cache(cache_dir, api_port, "cur", "old-revision")
        old_directory = paths["nested_config"].parent
        paths["nested_config"].write_text(paths["nested_config"].read_text().replace(
            'fleet.interval_sec: "3600"', 'fleet.interval_sec: "2"'))
        _set_follow_symlinks(paths["nested_config"], follow_symlinks)
        if not follow_symlinks:
            make_link(old_directory / "external", victim.parent, directory=True)
            if os.name != "nt":
                make_link(old_directory / "dangling", tmp_path / "missing")
            (old_directory / ".hidden").write_text("remove me")
    config = _fleet_config(cache_dir, api_port, marker)
    with FleetAPIServer(api_port, config, _fleet_files_payload()) as api:
        api.httpd.file_failures = 1
        service = FluentBitTestService(str(config_path), extra_env={"TZ": "UTC"})
        try:
            service.start()
            _wait_for_log_contains(service, "unable to write fleet files safely", timeout=45)
            _wait_for_log_contains(service, marker, timeout=45)
            if old_directory is not None:
                service.wait_for_condition(lambda: not old_directory.exists(), timeout=45,
                                           interval=0.5, description="old revision cleanup")
        finally:
            service.stop()
        assert sum(r["path"].endswith("/files") for r in api.requests) >= 2
    assert victim.read_text() == "untouched"


def test_fleet_rejects_header_symlink_before_download(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    _set_follow_symlinks(config_path, False)
    base_dir = _fleet_base_dir(cache_dir)
    base_dir.mkdir(parents=True)
    victim = tmp_path / "header-victim"
    victim.write_text("untouched")
    make_link(base_dir / "header.yaml", victim)
    with FleetAPIServer(api_port, _fleet_config(cache_dir, api_port, "must-not-reload")) as api:
        service = FluentBitTestService(str(config_path))
        try:
            service.start()
            _wait_for_log_contains(service, "unable to create fleet header safely")
        finally:
            service.stop()
        assert not any(r["path"].endswith("/config") for r in api.requests)
    assert victim.read_text() == "untouched"
    assert not (base_dir / "new.ref").exists()


def test_fleet_failed_attachment_cleanup_preserves_link_target(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "retried-after-blocked-attachment"
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port, interval_sec="2")
    timestamp = int(parsedate_to_datetime(LAST_MODIFIED).timestamp())
    staged = _fleet_base_dir(cache_dir) / str(timestamp)
    staged.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "keep"
    victim.write_text("untouched")
    make_link(staged / PARSER_FILE, outside, directory=True)

    with FleetAPIServer(api_port, _fleet_config(cache_dir, api_port, marker),
                       _fleet_files_payload()) as api:
        service = FluentBitTestService(str(config_path), extra_env={"TZ": "UTC"})
        try:
            service.start()
            _wait_for_log_contains(service, "unable to write fleet files safely", timeout=45)
            _wait_for_log_contains(service, marker, timeout=45)
        finally:
            service.stop()
        assert sum(r["path"].endswith("/files") for r in api.requests) >= 2
    assert victim.read_text() == "untouched"
    assert (staged / PARSER_FILE).is_file()


def test_fleet_hardened_migration_rejects_linked_destination_parent(tmp_path):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    paths = _write_old_cache(cache_dir, api_port, "cur", "migration-must-not-reload")
    outside = tmp_path / "outside"
    destination = paths["nested_config"]
    destination.parent.rename(outside)
    (outside / destination.name).write_text(paths["flat_config"].read_text())
    make_link(destination.parent, outside, directory=True)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    _set_follow_symlinks(config_path, False)
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        _wait_for_log_contains(service, "unable to open migrated config safely")
    finally:
        service.stop()
    assert paths["flat_config"].is_file()


@pytest.mark.parametrize("follow_symlinks", [True, False], ids=["follow", "harden"])
def test_fleet_migration_source_symlink_policy(tmp_path, follow_symlinks):
    api_port = find_available_port()
    cache_dir = tmp_path / "fleet-cache"
    marker = "migration-source-config"
    paths = _write_old_cache(cache_dir, api_port, "cur", marker)
    source = tmp_path / "external.yaml"
    paths["flat_config"].rename(source)
    make_link(paths["flat_config"], source)
    config_path = _write_bootstrap_config(tmp_path, cache_dir, api_port)
    _set_follow_symlinks(config_path, follow_symlinks)
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        _wait_for_log_contains(service, marker if follow_symlinks else "unable to read file for migration")
    finally:
        service.stop()
    assert paths["nested_config"].exists() == follow_symlinks
    assert source.is_file()
