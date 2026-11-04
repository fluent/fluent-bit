"""Opt-in real-plugin HTTPS tests in a private Docker network."""

import os
from types import SimpleNamespace

import pytest

from reproduce import PUBLIC_IMAGE, run_case


@pytest.fixture
def options(tmp_path):
    image = os.environ.get("KUSTO_TEST_IMAGE")
    if not image:
        pytest.skip("Set KUSTO_TEST_IMAGE to a built Linux Kusto test image; Docker is required")
    return SimpleNamespace(
        image=image,
        helper_image=os.environ.get("KUSTO_HELPER_IMAGE", image),
        ca_image=PUBLIC_IMAGE,
        ca_source="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        ca_target="/etc/ssl/certs/ca-bundle.crt",
        result=str(tmp_path / "result.json"),
        material_dir=None,
        seconds=60,
        stop_after_rotations=0,
        memory=1024 if os.environ.get("VALGRIND") == "1" else 512,
        outputs=2,
        resources=3,
        workers=2,
        delay=0.1,
        verify_hostname=True,
        wrong_hostname=False,
        split_hosts=False,
        untrusted=False,
        fail_identity=False,
        buffering=False,
        valgrind=os.environ.get("VALGRIND") == "1",
    )


def assert_clean(result, options):
    assert not result["state"]["OOMKilled"]
    assert result["state"]["ExitCode"] == 0
    if options.valgrind:
        assert result["valgrind_clean"], "See result.valgrind.log for checker errors"
    assert not result["requests"].get("unexpected", 0)
    assert not result["requests"].get("unexpected-command", 0)


def test_refresh_and_failed_candidate_recovery(options):
    options.fail_identity = True
    options.split_hosts = True
    options.seconds = 600
    options.stop_after_rotations = 3
    result = run_case(options)
    assert_clean(result, options)
    assert result["requests"].get("identity-failure", 0) > 0
    assert result["requests"].get("blob", 0) > 0
    assert result["requests"].get("queue", 0) > 0
    assert len(result["rotations"]) == options.outputs
    assert min(result["rotations"].values()) >= 3
    assert len(result["blob_cleanups"]) == options.outputs
    assert len(result["queue_cleanups"]) == options.outputs
    assert {"mock.local", "login.microsoftonline.com", "blob.local", "queue.local"} <= set(result["sni"])


@pytest.mark.parametrize("failure", ["untrusted", "wrong_hostname"])
def test_certificate_rejection(options, failure):
    options.seconds = 15
    options.outputs = 1
    options.workers = 1
    setattr(options, failure, True)
    result = run_case(options)
    assert_clean(result, options)
    assert result["tls_errors"] > 0
    assert result["requests"].get("blob", 0) == 0
    assert result["requests"].get("queue", 0) == 0


def test_buffered_shutdown(options):
    options.buffering = True
    options.outputs = 1
    options.workers = 1
    options.seconds = 15
    result = run_case(options)
    assert_clean(result, options)
    assert result["requests"].get("blob", 0) > 0
    assert result["requests"].get("queue", 0) > 0
