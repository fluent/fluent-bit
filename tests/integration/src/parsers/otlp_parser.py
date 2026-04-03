from google.protobuf.json_format import MessageToDict

def parse_trace_request(trace_request):
    return MessageToDict(trace_request)

def parse_metric_request(metric_request):
    return MessageToDict(metric_request)

def parse_log_request(log_request):
    return MessageToDict(log_request)
