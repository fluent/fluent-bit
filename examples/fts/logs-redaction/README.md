# FTS logs: redaction and enrichment

[`policy.lua`](policy.lua) processes the OpenTelemetry logs of a `checkout`
service:

1. Drops records whose `http.route` attribute is `/healthz`.
2. Replaces the values of `password`, `authorization`, `token` and `card` keys
   anywhere in the body with `[REDACTED]`.
3. Masks e-mail addresses and `token=` values inside the free-form `msg` text.
4. Replaces the `user.email` attribute with `user.email_domain`.
5. Sets the OpenTelemetry severity from the body `level` field.
6. Adds `deployment.environment.name` to the resource and `policy.name` to
   the log attributes.

## Run

```shell
examples/fts/run.sh examples/fts/logs-redaction
```

Or by hand, from this directory:

```shell
../../../build/bin/fluent-bit -c fluent-bit.yaml
# in another terminal
curl -H 'Content-Type: application/json' --data-binary @input.json \
     http://127.0.0.1:4318/v1/logs
```

## Expected output

The complete output is in [`expected-output.json`](expected-output.json).
[`input.json`](input.json) has three records; the health check is dropped and
the other two become:

| Field | Input | Output |
| ----- | ----- | ------ |
| `user.password` | `hunter2` | `[REDACTED]` |
| `headers.Authorization` | `Bearer abc123` | `[REDACTED]` (matching ignores case) |
| `card` | map with `number` and `expiry` | `[REDACTED]` (the whole value is replaced) |
| `db_password` | `not-a-match` | unchanged (keys must match exactly) |
| `msg` | `login succeeded for ana@example.com` | `login succeeded for <email>` |
| `msg` | `payment failed token=tok_live_42` | `payment failed token=[REDACTED]` |
| `attempt` | `intValue` 3 | `intValue` 3 (integer type preserved) |
| attribute `user.email` | `ana@example.com` | removed; `user.email_domain` is `example.com` |
| severity | none | `severityText` `info`/`error`, `severityNumber` 9/17 |
| resource | `service.name` | adds `deployment.environment.name: production` |

## Notes

- `fb.redact` matches whole keys, so `db_password` is kept. List every key name
  you need, or walk the map yourself when you need prefix or pattern matches.
- Key redaction does not read strings. Secrets inside text, such as the `msg`
  field here, need explicit string rules like `scrub()`, and those rules only
  catch the formats they describe.
- `fb.redact` only visits the value it is given. This policy redacts the body;
  attributes, resource attributes and metadata need their own calls.
- The processor keeps the default `error_mode: drop`, so a record whose policy
  fails is removed instead of forwarded unredacted.
