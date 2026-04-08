#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2024 The Fluent Bit Authors
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
import logging
import gzip
import threading
import time

from flask import Flask, request, jsonify, Response
from werkzeug.serving import make_server

app = Flask(__name__)
data_storage = {"payloads": [], "requests": []}
MOCK_JWKS_BODY = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test",
            "n": "xCUx72fXOyrjUZiiPJZIa7HtYHdQo_LAAkYG3yAcl1mwmh8pXrXB71xSDBI5SZDtKW4g6FEzYmP0jv3xwBdrZO2HQYwdxpCLhiMKEF0neC5w4NsjFlZKpnO53GN5W_c95bEhlVbh7O2q3PZVDhF5x9bdjlDS84NA0CY2l10UbSvIz12XR8uXqt6w9WVznrCe7ucSex3YPBTwll8Tm5H1rs1tPSx_9D0CJtZvxhKfgJtDyJJmV9syI6hlRgXnAsOonycOGSLryaIBtttxKUwy6QQkA-qSLZe2EcG2XoeBy10geOZ4WKGRiGubuuDpB1yFFy4mXQULJF6anO2osE31SQ",
            "e": "AQAB",
        }
    ]
}
response_config = {
    "status_code": 200,
    "body": {"status": "received"},
    "content_type": "application/json",
    "delay_seconds": 0,
    "stream_fragments": None,
    "fragment_delay_seconds": 0,
    "hang_before_response": False,
    "hang_after_fragment_index": None,
}
oauth_token_response = {
    "status_code": 200,
    "content_type": "application/json",
    "delay_seconds": 0,
    "hang_before_response": False,
    "stream_fragments": None,
    "fragment_delay_seconds": 0,
    "hang_after_fragment_index": None,
    "body": {
        "access_token": "oauth-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
    },
}
logger = logging.getLogger(__name__)
server_thread = None
server_instances = []
shutdown_event = threading.Event()


def _sleep_interruptible(seconds):
    if seconds <= 0:
        return

    deadline = time.time() + seconds

    while time.time() < deadline:
        if shutdown_event.wait(timeout=min(0.1, deadline - time.time())):
            break


def _wait_for_shutdown():
    shutdown_event.wait(timeout=30)


def reset_http_server_state():
    shutdown_event.clear()
    data_storage["payloads"] = []
    data_storage["requests"] = []
    server_instances.clear()
    response_config.update(
        {
            "status_code": 200,
            "body": {"status": "received"},
            "content_type": "application/json",
            "delay_seconds": 0,
            "stream_fragments": None,
            "fragment_delay_seconds": 0,
            "hang_before_response": False,
            "hang_after_fragment_index": None,
        }
    )
    oauth_token_response.update(
        {
            "status_code": 200,
            "content_type": "application/json",
            "delay_seconds": 0,
            "hang_before_response": False,
            "stream_fragments": None,
            "fragment_delay_seconds": 0,
            "hang_after_fragment_index": None,
            "body": {
                "access_token": "oauth-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        }
    )


def configure_http_response(*, status_code=None, body=None, content_type=None,
                            delay_seconds=None, stream_fragments=None,
                            fragment_delay_seconds=None,
                            hang_before_response=None,
                            hang_after_fragment_index=None):
    if status_code is not None:
        response_config["status_code"] = status_code
    if body is not None:
        response_config["body"] = body
    if content_type is not None:
        response_config["content_type"] = content_type
    if delay_seconds is not None:
        response_config["delay_seconds"] = delay_seconds
    if stream_fragments is not None:
        response_config["stream_fragments"] = list(stream_fragments)
    if fragment_delay_seconds is not None:
        response_config["fragment_delay_seconds"] = fragment_delay_seconds
    if hang_before_response is not None:
        response_config["hang_before_response"] = hang_before_response
    if hang_after_fragment_index is not None:
        response_config["hang_after_fragment_index"] = hang_after_fragment_index


def configure_oauth_token_response(*, status_code=None, body=None,
                                   content_type=None,
                                   delay_seconds=None,
                                   hang_before_response=None,
                                   stream_fragments=None,
                                   fragment_delay_seconds=None,
                                   hang_after_fragment_index=None):
    if status_code is not None:
        oauth_token_response["status_code"] = status_code
    if body is not None:
        oauth_token_response["body"] = body
    if content_type is not None:
        oauth_token_response["content_type"] = content_type
    if delay_seconds is not None:
        oauth_token_response["delay_seconds"] = delay_seconds
    if hang_before_response is not None:
        oauth_token_response["hang_before_response"] = hang_before_response
    if stream_fragments is not None:
        oauth_token_response["stream_fragments"] = list(stream_fragments)
    if fragment_delay_seconds is not None:
        oauth_token_response["fragment_delay_seconds"] = fragment_delay_seconds
    if hang_after_fragment_index is not None:
        oauth_token_response["hang_after_fragment_index"] = hang_after_fragment_index


def _stream_fragments(config):
    hang_after_fragment_index = config["hang_after_fragment_index"]

    for fragment in config["stream_fragments"]:
        if isinstance(fragment, str):
            fragment = fragment.encode("utf-8")

        yield fragment

        if hang_after_fragment_index == 0:
            _wait_for_shutdown()
            return

        if hang_after_fragment_index is not None:
            hang_after_fragment_index -= 1

        if config["fragment_delay_seconds"]:
            _sleep_interruptible(config["fragment_delay_seconds"])


def _build_streaming_response(config):
    return Response(
        _stream_fragments(config),
        status=config["status_code"],
        content_type=config["content_type"],
        direct_passthrough=True,
    )


def _build_response():
    if response_config["delay_seconds"]:
        _sleep_interruptible(response_config["delay_seconds"])

    if response_config["hang_before_response"]:
        _wait_for_shutdown()
        return Response(status=503)

    if response_config["stream_fragments"] is not None:
        return _build_streaming_response(response_config)

    body = response_config["body"]
    if isinstance(body, (dict, list)):
        return jsonify(body), response_config["status_code"]

    return Response(
        body,
        status=response_config["status_code"],
        content_type=response_config["content_type"],
    )


def _record_request():
    raw_payload = request.get_data(cache=True)
    decoded_payload = _decode_payload(raw_payload)
    data = _decode_json_payload(decoded_payload)
    raw_data = raw_payload.decode("utf-8", errors="replace")
    decoded_data = decoded_payload.decode("utf-8", errors="replace")

    data_storage["payloads"].append(data)
    data_storage["requests"].append(
        {
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", errors="replace"),
            "method": request.method,
            "headers": dict(request.headers),
            "raw_data": raw_data,
            "decoded_data": decoded_data,
            "json": data,
        }
    )


def _decode_payload(raw_payload):
    if request.headers.get("Content-Encoding", "").lower() == "gzip":
        return gzip.decompress(raw_payload)

    return raw_payload


def _decode_json_payload(decoded_payload):
    if not decoded_payload:
        return None

    try:
        return json.loads(decoded_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


@app.route('/data', methods=['POST'])
@app.route('/shared', methods=['POST'])
@app.route('/solo', methods=['POST'])
@app.route('/dataCollectionRules/<path:subpath>', methods=['POST'])
def receive_data(subpath=None):
    _record_request()
    return _build_response()


@app.route('/services/collector', methods=['POST'])
@app.route('/services/collector/event', methods=['POST'])
@app.route('/services/collector/raw', methods=['POST'])
def receive_splunk_hec():
    _record_request()
    return _build_response()


@app.route('/jwks', methods=['GET'])
def jwks():
    return jsonify(MOCK_JWKS_BODY), 200


@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    _record_request()
    if oauth_token_response["delay_seconds"]:
        _sleep_interruptible(oauth_token_response["delay_seconds"])
    if oauth_token_response["hang_before_response"]:
        _wait_for_shutdown()
        return Response(status=503)
    if oauth_token_response["stream_fragments"] is not None:
        return _build_streaming_response(oauth_token_response)
    return jsonify(oauth_token_response["body"]), oauth_token_response["status_code"]


@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "pong"}), 200


@app.route('/shutdown', methods=['POST'])
def shutdown():
    logger.info("HTTP server shutdown requested")
    shutdown_event.set()
    for server_instance in list(server_instances):
        threading.Thread(target=server_instance.shutdown, daemon=True).start()
    return jsonify({"status": "shutting down"}), 200


def run_server(port=60000, *, use_tls=False, tls_crt_file=None, tls_key_file=None):
    ssl_context = None
    if use_tls:
        ssl_context = (tls_crt_file, tls_key_file)

    server_instance = make_server("0.0.0.0", port, app,
                                  threaded=True,
                                  ssl_context=ssl_context)
    server_instances.append(server_instance)
    server_instance.serve_forever()


def http_server_run(port=60000, *, use_tls=False, tls_crt_file=None, tls_key_file=None,
                    reset_state=True):
    global server_thread

    if reset_state:
        reset_http_server_state()

    logger.info("Starting HTTP server on port %s", port)
    server_thread = threading.Thread(
        target=run_server,
        kwargs={
            "port": port,
            "use_tls": use_tls,
            "tls_crt_file": tls_crt_file,
            "tls_key_file": tls_key_file,
        },
        daemon=True,
    )
    server_thread.start()
    return server_thread
