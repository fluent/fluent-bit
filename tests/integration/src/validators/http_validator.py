from parsers.http_parser import parse_http_payload

def validate_http_payload(payload, expected_payload):
    payload_dict = parse_http_payload(payload)
    return payload_dict == expected_payload
