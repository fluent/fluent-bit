Table of Contents
=================

   * [Basic Intro](#basic-intro)
   * [Development](#development)
      * [How To Build And Test](#how-to-build-and-test)
      * [Speed Up Local Development](#speed-up-local-development)
      * [Build And Run Unit Test](#build-and-run-unit-test)
   * [Features](#features)
      * [Support multiple syslog output](#support-multiple-syslog-output)
      * [Reconnect When Upstream Connection Has Failed Somehow](#reconnect-when-upstream-connection-has-failed-somehow)

# Basic Intro

The code base of this plugin is from out_file plugin

# Development
## How To Build And Test

```
cd build
cmake ..
make

# Run fluent-bit process
bin/fluent-bit -c ../conf/out_syslog.conf
```

## Speed Up Local Development

Only build in_cpu and output_syslog plugin:
```
cd build
# https://fluentbit.io/documentation/0.13/installation/build_install.html
cmake -DFLB_IN_FORWARD=Off -DFLB_IN_HEAD=Off -DFLB_IN_HEALTH=Off -DFLB_IN_KMSG=Off \
      -DFLB_IN_MEM=Off -DFLB_IN_RANDOM=Off -DFLB_IN_SERIAL=Off -DFLB_IN_STDIN=Off \
      -DFLB_IN_TCP=Off -DFLB_IN_MQTT=Off -DFLB_OUT_ES=Off -DFLB_OUT_FORWARD=Off \
      -DFLB_OUT_HTTP=Off -DFLB_OUT_NATS=Off -DFLB_OUT_PLOT=Off -DFLB_OUT_STDOUT=Off \
      -DFLB_OUT_TD=Off -DFLB_OUT_NULL=Off ../
make
```

## Build And Run Unit Test
```
cd build
cmake -DFLB_ALL=On -DFLB_WITHOUT_EXAMPLES=On $FLB_FLUSH $FLB_MEM -DFLB_TESTS_INTERNAL=On ../
make
make test
```

# Features

## Support multiple syslog output

TODO

## Reconnect When Upstream Connection Has Failed Somehow

TODO
