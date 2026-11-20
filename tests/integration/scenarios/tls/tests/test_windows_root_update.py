import hashlib
import os
import socket
import ssl
import subprocess
from pathlib import Path

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.skipif(os.name != "nt", reason="Windows certificate store")
def test_windows_certstore_client_certificate(tmp_path, monkeypatch):
    scenarios = Path(__file__).resolve().parents[2]
    cert_dir = scenarios / "in_splunk/certificate"
    cert = str(cert_dir / "certificate.pem")
    key = str(cert_dir / "private_key.pem")
    config = yaml.safe_load((scenarios / "in_http/config/in_http_http1_tls.yaml").read_text())
    config["service"]["log_level"] = "debug"
    config["pipeline"]["inputs"][0]["tls.verify_client_cert"] = "on"
    config["pipeline"]["outputs"] = [{"name": "null", "match": "*"}]
    config_file = tmp_path / "server.yaml"
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setenv("FLB_WINDOWS_AUTO_ROOT_UPDATE", "on")
    service = FluentBitTestService(config_file, extra_env={"CERTIFICATE_TEST": cert,
                                                           "PRIVATE_KEY_TEST": key})
    try:
        service.start()
        for _ in range(2):
            with pytest.raises(requests.exceptions.ConnectionError):
                requests.get(f"https://localhost:{service.flb_listener_port}/",
                             cert=(cert, key), verify=cert, timeout=5)
    finally:
        service.stop()
    log = Path(service.flb.log_file).read_text(encoding="utf-8", errors="replace")
    assert log.count("certificate verify failed") == 2
    assert log.count("scheduled Windows certificate chain lookup") == 1


@pytest.mark.skipif(
    os.name != "nt" or os.getenv("FLB_TEST_WINDOWS_ROOT_DOWNLOAD") != "1",
    reason="requires Windows Update and a connection to DigiCert's public TLS demo",
)
@pytest.mark.parametrize(("name", "thumbprint"), [
    ("rsa4096", "a78849dc5d7c758c8cde399856b3aad0b2a57135"),
    ("ecc-p384", "17f3de5e9f0f19e98ef61f32266e20c407ae30ee"),
])
def test_windows_certstore_download(name, thumbprint):
    def installed():
        return any(encoding == "x509_asn" and hashlib.sha1(cert).hexdigest() == thumbprint
                   for cert, encoding, _ in ssl.enum_certificates("ROOT"))

    if installed():
        pytest.skip("demo root is already installed")

    host = f"digicert-tls-{name}-root-g5.chain-demos.digicert.com"
    address = socket.gethostbyname(host)
    result = subprocess.run([
        os.environ["FLUENT_BIT_BINARY"], "-i", f"health://{address}:443",
        "-p", "tls=on", "-p", f"tls.vhost={host}", "-p", "tls.verify=on",
        "-p", "tls.verify_hostname=on", "-t", "probe", "-o", "stdout", "-m", "probe",
        "-o", "exit", "-m", "probe", "-p", "flush_count=30", "-f", "1", "-v",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60, check=True)
    assert result.stdout.count("scheduled Windows certificate chain lookup") == 1, result.stdout
    assert "Windows resolved the peer certificate chain" in result.stdout, result.stdout
    assert '"alive"=>true' in result.stdout, result.stdout
    assert installed()
