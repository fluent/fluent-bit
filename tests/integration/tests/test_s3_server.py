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

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

from src.server import s3_server


def test_tagged_upload_barrier_releases_distinct_tags():
    barrier = s3_server.TaggedUploadBarrier(["first", "second"], timeout=1)
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(barrier.wait, "first")
        second = workers.submit(barrier.wait, "second")
        assert first.result() is True
        assert second.result() is True
    assert barrier.wait("first") is None


def test_tagged_upload_barrier_detects_serialized_requests():
    barrier = s3_server.TaggedUploadBarrier(["first", "second"], timeout=0.01)
    assert barrier.wait("first") is False
    assert barrier.wait("second") is False


def test_request_start_is_captured_before_reading_body(monkeypatch):
    calls = []
    handler = s3_server._S3RequestHandler.__new__(s3_server._S3RequestHandler)
    handler.headers = {"Content-Length": "4"}
    handler.command = "PUT"
    handler.path = "/bucket/tag/key"
    handler.rfile = Mock()

    def started():
        calls.append("start")
        return 1.0

    def read(size):
        calls.append("read")
        return b"body"

    handler.rfile.read.side_effect = read
    monkeypatch.setattr(s3_server.time, "monotonic", started)
    monkeypatch.setitem(s3_server.data_storage, "requests", [])

    request = handler._record_request()

    assert calls == ["start", "read"]
    assert request["started"] == 1.0
    assert request["body"] == b"body"
