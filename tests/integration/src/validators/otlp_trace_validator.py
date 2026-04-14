from parsers.otlp_parser import parse_trace_request

def validate_trace_data(trace_request, expected_span_name):
    trace_data_dict = parse_trace_request(trace_request)
    spans = trace_data_dict["resourceSpans"][0]["instrumentationLibrarySpans"][0]["spans"]
    return any(span["name"] == expected_span_name for span in spans)
