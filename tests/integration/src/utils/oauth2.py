import base64
import json

from server.http_server import app, MOCK_JWKS_BODY


def duplicate_header_token(token, field):
    """Preserve duplicate members, which a Python dict would discard.

    The signature is unchanged. Tests must assert that no JWKS fetch occurs
    to distinguish header rejection from signature verification failure.
    """
    header = '{"alg":"RS256","kid":"test"'
    value = "test" if field == "kid" else "RS256"
    header += ("," + json.dumps(field) + ":" + json.dumps(value)) * 32 + "}"
    encoded = base64.urlsafe_b64encode(header.encode()).rstrip(b"=").decode()
    return encoded + "." + token.split(".", 1)[1]


def track_jwks_requests(monkeypatch, body=None):
    """Track fetches and optionally serve raw JSON containing duplicate members."""
    requests_seen = []
    if body is None:
        body = json.dumps(MOCK_JWKS_BODY)

    def jwks():
        requests_seen.append(True)
        return body, 200, {"Content-Type": "application/json"}

    monkeypatch.setitem(app.view_functions, "jwks", jwks)
    return requests_seen


def duplicate_jwks_body(field, first_value):
    key = MOCK_JWKS_BODY["keys"][0]
    # The final value is correct, so the original last-wins parser accepts it.
    prefix = json.dumps(field) + ":" + json.dumps(first_value)
    return '{"keys":[{' + prefix + "," + json.dumps(key)[1:] + "]}"
