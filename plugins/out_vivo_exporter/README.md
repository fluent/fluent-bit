# Vivo Exporter

The Vivo exporter exposes Fluent Bit data through an HTTP interface that streams
logs, metrics, and traces. Each response includes cursor headers that describe
the stream position so that clients can resume from the point they last read.

## Cursor headers

Responses always include the following headers:

- `Vivo-Stream-Start-ID`: The first record identifier included in the response
  body (when the body is non-empty).
- `Vivo-Stream-End-ID`: The last record identifier included in the response
  body (when the body is non-empty).
- `Vivo-Stream-Next-ID`: The identifier that will be assigned to the next
  record appended to the stream. This header is present even when the response
  body is empty so that clients can track the exporter position across polling
  intervals.

Clients should store the `Vivo-Stream-Next-ID` value and provide it in the next
request (for example via the `from` query parameter) to resume from where they
left off, regardless of whether any records were returned in the previous
response.
