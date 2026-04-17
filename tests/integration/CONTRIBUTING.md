# Contributing to Fluent Bit Test Suite

> note: this guide is still work in process

The way to contribute to this project is through the official Github Repository  [fluent/fluent-bit-test-suite](https://github.com/fluent/fluent-bit-test-suite). All contributions must adhere to this guidelines that aims to make easier it maintenance and high quality over time.

## Why contributing to this project ?

Fluent Bit is one of the widely deployed Telemetry Agent around the globe, millions of new deployments happens every single day. Contributing to this project aims to extend the testing of different areas under different complex configurations.

Our goal is to avoid regressions and making sure Fluent Bit can continue to grow in a healthy way.

## Guidelines

All the code in this project is based on Python 3.x and we have a few requirements:

### Code Style

Avoid using camelCase in variables, functions and method names, use the underscore (`_`) instead.

### GIT Commits

In open source project maintenance, having a clear history is key for us, for hence we expect full clarity in the commits. Clarity must be in the following places:

- commit prefix
- commit description

#### Commit Prefix and Descriptions

Commit _prefix_ __must not exceed 80__ characters in length. This help to readibility in the GIT log viewers. Make it short and straight to the point.

In _commit description_, make sure each line do not exceed __120 characters__. Here you have more flexibility to write more about the changes, just try to be inside the length limit of each line.

The project have specific components, we enforce that every commit that touches an interface or component be prefixed with that name. As of today we register the following components:

__scenarios__

An scenario defines a main type of pipeline or Fluent Bit component being tested, an example is:

- in-opentelemetry: changes applicable to OTLP input and OTLP round-trip tests
- in-splunk: changes applicable to Splunk input protocol tests
- in-elasticsearch: changes applicable to Elasticsearch input compatibility tests
- in-http: changes applicable to HTTP input end-to-end tests

For any code change that is happening inside [scenarios/in_opentelemetry](https://github.com/fluent/fluent-bit-test-suite/tree/main/scenarios/in_opentelemetry) the commit must be prefixed like this:

``` 
scenarios: in-opentelemetry: description of the change
```

Optionally you can add a third component that represents another file interface (without the extension `.py`) .

__server__

In the server components, we have helpers to implement 'fake servers' who mimic other projects that we use as receivers, e.g:

| server | description |
|--|--|
| [http](https://github.com/fluent/fluent-bit-test-suite/blob/main/src/server/http_server.py) | Simple HTTP server |
| [otlp](https://github.com/fluent/fluent-bit-test-suite/blob/main/src/server/otlp_server.py) | OpenTelemetry HTTP Server |
| [splunk](https://github.com/fluent/fluent-bit-test-suite/blob/main/src/server/splunk_server.py) | Splunk HTTP Server |

When modifying any of those servers or adding new ones, the commits must be prefixed like this:

```
server: http: some example descripition
```

### Naming

Prefer Fluent Bit internal plugin naming in test names and descriptions:

- `in_splunk`
- `in_elasticsearch`
- `in_http`

Scenario directory names may be broader for now, but new tests and updated assertions should follow the internal plugin names in function names, docs, and commit prefixes whenever practical.
Scenario directory names are now expected to follow the internal plugin names for maintained scenarios whenever possible.


##### Others

Commits should not modify files outside of the scope defined in the prefix, while there might be cases for exceptions we will handle those in the Pull Request review process.


### License

All code contributed to this project is under the terms of the Apache v2 License. All commits must be signed (DCO).
