# Standard Input

The __stdin__ plugin allows to retrieve valid JSON text messages over the standard input interface (stdin). In order to use it, specify the plugin name as the input, e.g:

```bash
$ ./bin/fluent-bit -i stdin -o stdout
```

A better example to demonstrate how it works will be through a _Bash_ script that generate messages and write them to [Fluent Bit](http://fluentbit.io). Write the following content in a file named _test.sh_:

```bash
#!/bin/sh

while :; do
  echo -n "{\"key\": \"some value\"}"
  sleep 1
done
```

Give the script execution permission:

```bash
$ chmod 755 test.sh
```

Now lets start the script and [Fluent Bit](http://fluentbit.io) in the following way:

```bash
$ ./test.sh | bin/fluent-bit -i stdin -o stdout -V
Fluent-Bit v0.2.0
Copyright (C) Treasure Data

[2015/07/29 13:51:02] [ info] Configuration
flush time     : 5 seconds
input plugins  : stdin
collectors     :
[2015/07/29 13:51:02] [ info] starting engine
[2015/07/29 13:51:02] [debug] in_stdin read() = 21
[2015/07/29 13:51:03] [debug] in_stdin read() = 21
[2015/07/29 13:51:04] [debug] in_stdin read() = 21
[2015/07/29 13:51:05] [debug] in_stdin read() = 21
[2015/07/29 13:51:06] [debug] in_stdin read() = 21
[0] {"key"=>"some value"}
[1] {"key"=>"some value"}
[2] {"key"=>"some value"}
[3] {"key"=>"some value"}
[4] {"key"=>"some value"}

```
