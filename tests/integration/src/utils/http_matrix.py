import os
import subprocess
import tempfile


PROTOCOL_CASES = [
    {
        "id": "http1_cleartext",
        "config_key": "http1_cleartext",
        "http_mode": "http1.1",
        "use_tls": False,
        "expected_http_version": "1.1",
    },
    {
        "id": "http2_cleartext_prior_knowledge",
        "config_key": "http2_cleartext",
        "http_mode": "http2-prior-knowledge",
        "use_tls": False,
        "expected_http_version": "2",
    },
    {
        "id": "http2_cleartext_upgrade_attempt",
        "config_key": "http2_cleartext",
        "http_mode": "http2",
        "use_tls": False,
        "expected_http_version": "1.1",
    },
    {
        "id": "http2_cleartext_upgrade_fallback_http1",
        "config_key": "http1_cleartext",
        "http_mode": "http2",
        "use_tls": False,
        "expected_http_version": "1.1",
    },
    {
        "id": "http1_tls",
        "config_key": "http1_tls",
        "http_mode": "http1.1",
        "use_tls": True,
        "expected_http_version": "1.1",
    },
    {
        "id": "http2_tls_alpn",
        "config_key": "http2_tls",
        "http_mode": "http2",
        "use_tls": True,
        "expected_http_version": "2",
    },
    {
        "id": "http2_tls_fallback_http1",
        "config_key": "http1_tls",
        "http_mode": "http2",
        "use_tls": True,
        "expected_http_version": "1.1",
    },
]


def curl_supports_http2():
    result = subprocess.run(
        ["curl", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    return "HTTP2" in result.stdout or "HTTP2" in first_line


def run_curl_request(
    url,
    payload=None,
    *,
    method="POST",
    headers=None,
    http_mode,
    insecure_tls=False,
    ca_cert_path=None,
    include_headers=False,
    extra_args=None,
):
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "-",
        "--write-out",
        "\n__META__%{http_code} %{http_version}",
        "--max-time",
        "10",
        "-X",
        method,
    ]

    header_file = None
    if include_headers:
        header_file = tempfile.NamedTemporaryFile(mode="w+b", delete=False)
        header_file.close()
        command.extend(["--dump-header", header_file.name])

    for header in headers or []:
        command.extend(["-H", header])

    stdin_payload = None
    if payload is not None:
        command.extend(["--data-binary", "@-"])
        stdin_payload = payload if isinstance(payload, bytes) else payload.encode()

    if http_mode == "http1.1":
        command.append("--http1.1")
    elif http_mode == "http2":
        command.append("--http2")
    elif http_mode == "http2-prior-knowledge":
        command.append("--http2-prior-knowledge")
    else:
        raise ValueError(f"Unsupported HTTP mode {http_mode}")

    if ca_cert_path:
        command.extend(["--cacert", ca_cert_path])
    elif insecure_tls:
        command.append("--insecure")

    if extra_args:
        command.extend(extra_args)

    command.append(url)

    try:
        result = subprocess.run(command, input=stdin_payload, capture_output=True, check=True)
        output = result.stdout.decode()
        body, _, meta = output.rpartition("\n__META__")
        status_code, http_version = meta.strip().split(" ", 1)

        response = {
            "body": body,
            "status_code": int(status_code),
            "http_version": http_version,
        }

        if include_headers and header_file:
            with open(header_file.name, "r", encoding="utf-8", errors="replace") as file:
                response["headers_raw"] = file.read()

        return response
    finally:
        if header_file:
            try:
                os.unlink(header_file.name)
            except FileNotFoundError:
                pass
