#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2026 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import json
import os
import shutil

import pytest
import requests
import yaml

from server.s3_server import data_storage, s3_server_run, s3_server_stop
from utils.test_service import FluentBitTestService


def config_section(config_format, section, properties):
    if config_format == "yaml":
        if section == "service":
            return yaml.safe_dump({"service": properties})
        return yaml.safe_dump({"pipeline": {section + "s": [properties]}})
    lines = [f"[{section.upper()}]"]
    lines.extend(f"    {key} {value}" for key, value in properties.items())
    return "\n".join(lines) + "\n"


class ConfigProjection:
    """Publish complete generations like a mounted ConfigMap, or ordinary files."""

    def __init__(self, directory, projected):
        self.directory = directory
        self.projected = projected
        self.generation = None
        self.names = set()

    def publish(self, files, generation):
        if not self.projected:
            for name in self.names - files.keys():
                (self.directory / name).unlink()
            for name, contents in files.items():
                (self.directory / name).write_text(contents, encoding="utf-8")
        else:
            target = self.directory / f"..generation-{generation}"
            target.mkdir()
            for name, contents in files.items():
                (target / name).write_text(contents, encoding="utf-8")
            pending = self.directory / "..data_tmp"
            pending.symlink_to(target.name, target_is_directory=True)
            pending.replace(self.directory / "..data")
            for name in files.keys() - self.names:
                (self.directory / name).symlink_to(f"..data/{name}")
            for name in self.names - files.keys():
                (self.directory / name).unlink()
            if self.generation is not None:
                shutil.rmtree(self.generation)
            self.generation = target
        self.names = set(files)


@pytest.mark.parametrize("config_format", ["conf", "yaml"], ids=["classic", "yaml"])
@pytest.mark.parametrize("projected", [False, True], ids=["files", "configmap"])
def test_http_reload_glob_output_changes(tmp_path, monkeypatch, config_format, projected):
    if projected and os.name == "nt":
        pytest.skip("ConfigMap projection uses POSIX symlinks")

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    working_dir = tmp_path / "working"
    working_dir.mkdir()
    monkeypatch.chdir(working_dir)

    main_name = f"fluent-bit.{config_format}"
    patterns = [f"*_{kind}.{config_format}" for kind in ("inputs", "filters", "outputs")]
    main = config_section(config_format, "service", {
        "flush": 1,
        "grace": 1,
        "log_level": "debug",
        "http_server": "on",
        "http_listen": "127.0.0.1",
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        "hot_reload": "on",
    })
    if config_format == "yaml":
        main += yaml.safe_dump({"includes": patterns})
    else:
        main += "\n" + "".join(f"@INCLUDE {pattern}\n" for pattern in patterns)

    def output(bucket):
        return config_section(config_format, "output", {
            "name": "s3",
            "match": "reload.test",
            "bucket": bucket,
            "region": "us-east-1",
            "endpoint": "http://127.0.0.1:${TEST_SUITE_HTTP_PORT}",
            "use_put_object": "on",
            "total_file_size": "1M",
            "upload_timeout": "1s",
            "s3_key_format": "/$TAG/$UUID",
            "store_dir": (tmp_path / f"store-{bucket}").as_posix(),
        })

    files = {
        main_name: main,
        f"base_inputs.{config_format}": config_section(config_format, "input", {
            "name": "http",
            "listen": "127.0.0.1",
            "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
        }),
        f"base_filters.{config_format}": config_section(config_format, "filter", {
            "name": "modify",
            "match": "reload.test",
            "add": "included_filter yes",
        }),
        f"base_outputs.{config_format}": output("baseline"),
    }
    projection = ConfigProjection(config_dir, projected)
    projection.publish(files, 0)
    service = FluentBitTestService(
        str(config_dir / main_name),
        extra_env={
            "AWS_ACCESS_KEY_ID": "test-access-key",
            "AWS_SECRET_ACCESS_KEY": "test-secret-key",
            "AWS_EC2_METADATA_DISABLED": "true",
        },
        pre_start=lambda service: s3_server_run(service.test_suite_http_port),
        post_stop=lambda service: s3_server_stop(),
        shutdown_timeout=30,
    )

    def received(bucket, message):
        return any(
            request["method"] == "PUT"
            and request.get("status") == 200
            and request["path"].startswith(f"/{bucket}/")
            and any(
                record.get("message") == message and record.get("included_filter") == "yes"
                for record in map(json.loads, request["body"].splitlines())
            )
            for request in list(data_storage["requests"])
        )

    def send_and_check(message, buckets):
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/reload.test",
            json={"message": message}, timeout=5,
        )
        response.raise_for_status()
        for bucket in buckets:
            service.wait_for_condition(
                lambda: received(bucket, message), timeout=30,
                description=f"{message} uploaded to {bucket}",
            )

    try:
        service.start()
        pid = service.flb.process.pid
        assert service.flb.get_reload_status()["hot_reload_count"] == 0
        send_and_check("before", ["baseline"])

        for count, added in enumerate((True, False, True), start=1):
            extra_name = f"hello-world_outputs.{config_format}"
            if added:
                files[extra_name] = output("added")
            else:
                del files[extra_name]
            projection.publish(files, count)
            assert service.flb.trigger_http_reload()["reload"] == "done"
            status = service.flb.wait_for_hot_reload_count(count, timeout=30)
            assert status["hot_reload_count"] == count
            assert service.flb.process.pid == pid
            send_and_check(f"generation-{count}", ["baseline", "added"] if added else ["baseline"])
    finally:
        service.stop()

    assert not received("added", "before")
    assert not received("added", "generation-2")
