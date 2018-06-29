# Basic Intro

The code base of this plugin is from out_file plugin

# How to build and test

```
$ cd build
$ cmake ..
$ make flb-plugin-out_syslog
$ # or: make flb-plugin-out_syslog/fast
$ bin/fluent-bit -c ../conf/out_syslog.conf
```

# Support multiple syslog output
