"""Blob outputs enforce their policy when reopening registered file paths."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest
import yaml

from utils.filesystem import make_link
from utils.test_service import FluentBitTestService


class UploadHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.uploads.append(body)
        self.send_response(201 if self.server.plugin == "azure_blob" else 200)
        self.send_header("ETag", '"test-etag"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.mark.parametrize("plugin", ["s3", "azure_blob"])
@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
@pytest.mark.parametrize("path_kind", ["regular", "leaf", "ancestor"])
def test_blob_upload_file_policy(tmp_path, plugin, follow_symlinks, path_kind):
    payload = b"blob policy test payload"
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "data.bin"
    target.write_bytes(payload)
    if path_kind == "leaf":
        source = tmp_path / "linked.bin"
        make_link(source, target)
    elif path_kind == "ancestor":
        link = tmp_path / "linked"
        make_link(link, outside, directory=True)
        source = link / "data.bin"
    else:
        source = target

    server = ThreadingHTTPServer(("127.0.0.1", 0), UploadHandler)
    server.daemon_threads = True
    server.plugin = plugin
    server.uploads = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = {
        "name": plugin, "match": "*", "workers": 1,
        "endpoint": f"http://127.0.0.1:{server.server_port}",
        "upload_parts_timeout": "1s",
    }
    if follow_symlinks is not None:
        output["follow_symlinks"] = follow_symlinks
    if plugin == "s3":
        output.update({
            "bucket": "test-bucket", "region": "us-east-1",
            "use_put_object": True, "total_file_size": "1048576",
            "upload_timeout": "1s", "s3_key_format": "/$TAG/$UUID",
            "store_dir": str(tmp_path / "store"),
            "blob_database_file": str(tmp_path / "output.db"),
            "part_size": "5242880",
        })
    else:
        output.update({
            "account_name": "testaccount", "container_name": "testcontainer",
            "shared_key": base64.b64encode(b"test-key").decode(),
            "blob_type": "blockblob", "auto_create_container": False,
            "emulator_mode": True, "database_file": str(tmp_path / "output.db"),
        })
    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "debug",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            # Keep discovery permissive to verify the output's independent policy.
            "inputs": [{"name": "blob", "tag": "blob.test", "path": str(source),
                        "database_file": str(tmp_path / "input.db"),
                        "upload_success_action": "add_suffix",
                        "upload_success_suffix": ".done",
                        "scan_refresh_interval": "1s"}],
            "outputs": [output],
        },
    }
    config_path = tmp_path / "test.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path), extra_env={
        "AWS_ACCESS_KEY_ID": "test-access-key",
        "AWS_SECRET_ACCESS_KEY": "test-secret-key",
        "AWS_EC2_METADATA_DISABLED": "true",
    })
    try:
        service.start()
        if follow_symlinks is False and path_kind != "regular":
            service.wait_for_condition(
                lambda: "cannot read file part" in Path(service.flb.log_file).read_text(),
                timeout=30, description="hardened output rejecting a symlink",
            )
            assert payload not in server.uploads
        else:
            service.wait_for_condition(
                lambda: payload in server.uploads,
                timeout=30, description="blob contents uploaded",
            )
            service.wait_for_condition(
                lambda: Path(str(source) + ".done").exists(),
                timeout=30, description="input delivery notification processed",
            )
    finally:
        try:
            service.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
