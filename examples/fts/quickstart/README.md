# FTS quickstart

A `dummy` input generates one record and an inline FTS policy redacts its
`password` field and adds an `environment` field. No other tools are needed.

```shell
../../../build/bin/fluent-bit -c fluent-bit.yaml
```

Stop it with Ctrl-C. Expected output, also in
[`expected-output.json`](expected-output.json):

```json
{"user":"ana","password":"[REDACTED]","path":"/login","status":200,"environment":"dev"}
```

`status` is still the integer `200`: FTS only changes the values a policy
writes.
