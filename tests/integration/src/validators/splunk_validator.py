from parsers.splunk_parser import parse_splunk_event

def validate_splunk_event(event, expected_event):
    event_dict = parse_splunk_event(event)
    return event_dict == expected_event
