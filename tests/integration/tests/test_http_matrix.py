import subprocess
from unittest.mock import Mock

import pytest

from utils import http_matrix
from utils.input_pause_resume import run_curl_without_check


@pytest.mark.parametrize("mode", ["http2", "http2-prior-knowledge"])
@pytest.mark.parametrize("unchecked", [False, True])
def test_http2_requests_skip_without_curl_capability(monkeypatch, mode, unchecked):
    monkeypatch.setattr(http_matrix.shutil, "which", lambda name: "selected-curl")
    run = Mock(return_value=subprocess.CompletedProcess(
        [], 0, stdout="curl with HTTP2 in a description\nFeatures: SSL IPv6\n"
    ))
    monkeypatch.setattr(http_matrix.subprocess, "run", run)
    with pytest.raises(pytest.skip.Exception, match="Selected curl lacks HTTP2 support: selected-curl"):
        if unchecked:
            run_curl_without_check("http://localhost/", b"{}", [], http_mode=mode, max_time=1)
        else:
            http_matrix.run_curl_request("http://localhost/", http_mode=mode)
    run.assert_called_once_with(
        ["selected-curl", "--version"], capture_output=True, text=True, check=True
    )


@pytest.mark.parametrize("mode", ["http1.1", "http2", "http2-prior-knowledge"])
def test_supported_requests_preserve_curl_failures(monkeypatch, mode):
    monkeypatch.setattr(http_matrix.shutil, "which", lambda name: "selected-curl")
    failure = subprocess.CalledProcessError(7, ["selected-curl"], stderr=b"connect failed")
    results = [failure]
    if mode != "http1.1":
        results.insert(0, subprocess.CompletedProcess([], 0, stdout="Features: SSL HTTP2\n"))
    run = Mock(side_effect=results)
    monkeypatch.setattr(http_matrix.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError) as exc:
        http_matrix.run_curl_request("http://localhost/", http_mode=mode)
    assert exc.value is failure
    assert run.call_args.args[0][0] == "selected-curl"
