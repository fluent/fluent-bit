#!/bin/bash

# !! TODO: move to a Makefile

CGO_CFLAGS="-I${HOME}/src/fluent-bit/include -I${HOME}/src/fluent-bit/lib/monkey/include -I${HOME}/src/fluent-bit/build/lib/monkey/include/monkey -I${HOME}/src/fluent-bit/lib/cfl/include -I${HOME}/src/fluent-bit/lib/cfl/lib/xxhash -I${HOME}/src/fluent-bit/lib/cmetrics/include -I${HOME}/src/fluent-bit/lib/flb_libco -I${HOME}/src/fluent-bit/lib/c-ares-1.33.1/include -I${HOME}/src/fluent-bit/lib/msgpack-c/include -I${HOME}/src/fluent-bit/lib/ctraces/include -I${HOME}/src/fluent-bit/lib/ctraces/lib/mpack/src" CGO_LDFLAGS="-L${HOME}/src/fluent-bit/build/lib -lfluent-bit" sh -c 'echo CGO_CFLAGS=${CGO_CFLAGS}; echo CGO_LDFLAGS=${CGO_LDFLAGS}; go build -buildmode=c-shared -o build/bin/custom_extensions_go.so github.com/fluent/fluent-bit/plugins/custom_extensions_go'
