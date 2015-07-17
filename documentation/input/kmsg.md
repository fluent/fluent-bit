# Kernel Log Messages

The __kmsg__ input plugin reads the Linux Kernel log buffer since the beginning, it get every record and parse it field as priority, sequence, seconds, useconds, and message.

In order to read the Kernel log messages with [Fluent Bit](http://fluentbit.io), specify the following command line arguments:

```
$ ./bin/fluent-bit -i kmsg -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/17 15:45:15] [ info] Configuration
flush time     : 5 seconds
input plugins  : kmsg
collectors     :
[2015/07/17 15:45:15] [ info] starting engine
[2015/07/17 15:45:15] [debug] [in_kmsg] pri=6 seq=0 ts=1436877345 sec=0 usec=0 'Initializing cgroup subsys cpuset'
[2015/07/17 15:45:15] [debug] [in_kmsg] pri=6 seq=1 ts=1436877345 sec=0 usec=0 'Initializing cgroup subsys cpu'
[2015/07/17 15:45:15] [debug] [in_kmsg] pri=6 seq=2 ts=1436877345 sec=0 usec=0 'Initializing cgroup subsys cpuacct'
[2015/07/17 15:45:15] [debug] [in_kmsg] pri=5 seq=3 ts=1436877345 sec=0 usec=0 'Linux version 4.0.0-040000rc6-generic...
...
[TRUNCATED]
...
[0] [1437041863, {"priority"=>4, "sequence"=>2550, "sec"=>164518, "usec"=>0, "msg"=>" [<ffffffff817eb787>] ? schedule+0x37/0x90"}]
[1] [1437041863, {"priority"=>4, "sequence"=>2551, "sec"=>164518, "usec"=>0, "msg"=>" [<ffffffff817ef90d>] system_call_fastpath+0x16/0x1b"}]
[2] [1437041863, {"priority"=>4, "sequence"=>2552, "sec"=>164518, "usec"=>0, "msg"=>"---[ end trace d0cd9ee0013ccb72 ]---"}]
[3] [1437041896, {"priority"=>6, "sequence"=>2553, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211: Calling CRDA to update world regulatory domain"}]
[4] [1437041896, {"priority"=>6, "sequence"=>2554, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211: World regulatory domain updated:"}]
[5] [1437041896, {"priority"=>6, "sequence"=>2555, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:  DFS Master region: unset"}]
[6] [1437041896, {"priority"=>6, "sequence"=>2556, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (start_freq - end_freq @ bandwidth), (max_antenna_gain, max_eirp), (dfs_cac_time)"}]
[7] [1437041896, {"priority"=>6, "sequence"=>2557, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (2402000 KHz - 2472000 KHz @ 40000 KHz), (300 mBi, 2000 mBm), (N/A)"}]
[8] [1437041896, {"priority"=>6, "sequence"=>2558, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (2457000 KHz - 2482000 KHz @ 40000 KHz), (300 mBi, 2000 mBm), (N/A)"}]
[9] [1437041896, {"priority"=>6, "sequence"=>2559, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (2474000 KHz - 2494000 KHz @ 20000 KHz), (300 mBi, 2000 mBm), (N/A)"}]
[10] [1437041896, {"priority"=>6, "sequence"=>2560, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (5170000 KHz - 5250000 KHz @ 40000 KHz), (300 mBi, 2000 mBm), (N/A)"}]
[11] [1437041896, {"priority"=>6, "sequence"=>2561, "sec"=>164551, "usec"=>0, "msg"=>"cfg80211:   (5735000 KHz - 5835000 KHz @ 40000 KHz), (300 mBi, 2000 mBm), (N/A)"}]
[12] [1437050935, {"priority"=>4, "sequence"=>2562, "sec"=>173590, "usec"=>0, "msg"=>"applesmc: send_byte(0x80, 0x0300) fail: 0x40"}]
[13] [1437050935, {"priority"=>4, "sequence"=>2563, "sec"=>173590, "usec"=>0, "msg"=>"applesmc: F0Mn: write data fail"}]
[14] [1437051286, {"priority"=>4, "sequence"=>2564, "sec"=>173941, "usec"=>0, "msg"=>"applesmc: send_byte(0x98, 0x0300) fail: 0x40"}]
[15] [1437051286, {"priority"=>4, "sequence"=>2565, "sec"=>173941, "usec"=>0, "msg"=>"applesmc: F0Mn: write data fail"}]
[16] [1437061492, {"priority"=>4, "sequence"=>2566, "sec"=>184147, "usec"=>0, "msg"=>"applesmc: send_byte(0x38, 0x0300) fail: 0x40"}]
[17] [1437061492, {"priority"=>4, "sequence"=>2567, "sec"=>184147, "usec"=>0, "msg"=>"applesmc: F0Mn: write data fail"}]
[18] [1437066022, {"priority"=>4, "sequence"=>2568, "sec"=>188677, "usec"=>0, "msg"=>"applesmc: send_byte(0x58, 0x0300) fail: 0x40"}]
[19] [1437066022, {"priority"=>4, "sequence"=>2569, "sec"=>188677, "usec"=>0, "msg"=>"applesmc: F0Mn: write data fail"}]
```

As described above, the plugin processed all messages that the Linux Kernel reported, the output have been truncated for clarification.
