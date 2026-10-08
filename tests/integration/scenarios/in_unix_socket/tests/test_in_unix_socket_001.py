import os
from pathlib import Path
import socket
import tempfile

import pytest

from utils.fluent_bit_manager import FluentBitStartupError, fluent_bit_input_supports_config_property
from utils.test_service import FluentBitTestService

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Requires Unix sockets")
SCENARIOS = Path(__file__).resolve().parents[2]


@pytest.fixture(params=[
    ("in_http", "in_http_unix", socket.SOCK_STREAM),
    ("in_forward", "in_forward_unix", socket.SOCK_STREAM),
    ("in_syslog", "in_syslog_uds_stream_plaintext", socket.SOCK_STREAM),
    ("in_syslog", "in_syslog_uds_dgram_plaintext", socket.SOCK_DGRAM),
    ("in_unix_socket", "in_unix_socket", socket.SOCK_STREAM),
    ("in_unix_socket", "in_unix_socket", socket.SOCK_DGRAM),
], ids=["http", "forward", "syslog-stream", "syslog-dgram", "unix-stream", "unix-dgram"])
def unix_service(request):
    plugin, config, socket_type = request.param
    if plugin == "in_unix_socket" and not fluent_bit_input_supports_config_property("unix_socket", "socket_path"):
        pytest.skip("Requires a build with FLB_IN_UNIX_SOCKET=On")
    with tempfile.TemporaryDirectory(prefix="flb-unix-") as directory:
        path = Path(directory) / "input.sock"
        service = FluentBitTestService(SCENARIOS / plugin / "config" / f"{config}.yaml", extra_env={
            "HTTP_UNIX_PATH": path,
            "HTTP_UNIX_TLS": "off",
            "FORWARD_UNIX_PATH": path,
            "SYSLOG_SOCKET_PATH": path,
            "UNIX_SOCKET_PATH": path,
            "UNIX_SOCKET_MODE": "STREAM" if socket_type == socket.SOCK_STREAM else "DGRAM",
            "PARSERS_FILE_TEST": SCENARIOS.parents[2] / "conf" / "parsers.conf",
        })
        try:
            yield service, path, socket_type
        finally:
            service.stop()


def test_unix_socket_recovers_stale_file(unix_service):
    service, path, socket_type = unix_service
    with socket.socket(socket.AF_UNIX, socket_type) as stale:
        stale.bind(str(path))
    service.start()
    assert path.is_socket()
    service.stop()
    assert not path.exists()


@pytest.mark.parametrize("full_backlog", [False, True])
def test_unix_socket_preserves_active_listener(unix_service, full_backlog):
    service, path, socket_type = unix_service
    if full_backlog and socket_type == socket.SOCK_DGRAM:
        pytest.skip("Datagram sockets do not have a listen backlog")
    with socket.socket(socket.AF_UNIX, socket_type) as listener, socket.socket(socket.AF_UNIX) as client:
        listener.bind(str(path))
        if socket_type == socket.SOCK_STREAM:
            listener.listen(0 if full_backlog else 1)
            if full_backlog:
                client.connect(str(path))
        original = path.stat()
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert os.path.samestat(path.stat(), original)


@pytest.mark.parametrize("replacement_type", ["socket", "file", "symlink"])
def test_unix_socket_preserves_replacement(unix_service, replacement_type):
    service, path, socket_type = unix_service
    service.start()
    path.rename(path.with_suffix(".original"))
    with socket.socket(socket.AF_UNIX, socket_type) as replacement:
        if replacement_type == "socket":
            replacement.bind(str(path))
            if socket_type == socket.SOCK_STREAM:
                replacement.listen(1)
        elif replacement_type == "file":
            path.write_text("do not remove")
        else:
            path.symlink_to(path.with_suffix(".original"))
        original = path.lstat()
        service.stop()
        assert os.path.samestat(path.lstat(), original)
