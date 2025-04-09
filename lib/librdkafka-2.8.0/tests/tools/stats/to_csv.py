#!/usr/bin/env python3
#
# Parse librdkafka stats JSON from stdin, one stats object per line, pick out
# the relevant fields and emit CSV files suitable for plotting with graph.py
#

import sys
import json
from datetime import datetime
from collections import OrderedDict


def parse(linenr, string):
    try:
        js = json.loads(string)
    except Exception:
        return [], [], [], []

    dt = datetime.utcfromtimestamp(js['time']).strftime('%Y-%m-%d %H:%M:%S')

    top = {'0time': dt}
    topcollect = ['msg_cnt', 'msg_size']
    for c in topcollect:
        top[c] = js[c]

    top['msg_cnt_fill'] = (float(js['msg_cnt']) / js['msg_max']) * 100.0
    top['msg_size_fill'] = (float(js['msg_size']) / js['msg_size_max']) * 100.0

    collect = ['outbuf_cnt', 'outbuf_msg_cnt', 'tx',
               'waitresp_cnt', 'waitresp_msg_cnt', 'wakeups']

    brokers = []
    for b, d in js['brokers'].items():
        if d['req']['Produce'] == 0:
            continue

        out = {'0time': dt, '1nodeid': d['nodeid']}
        out['stateage'] = int(d['stateage'] / 1000)

        for c in collect:
            out[c] = d[c]

        out['rtt_p99'] = int(d['rtt']['p99'] / 1000)
        out['int_latency_p99'] = int(d['int_latency']['p99'] / 1000)
        out['outbuf_latency_p99'] = int(d['outbuf_latency']['p99'] / 1000)
        out['throttle_p99'] = d['throttle']['p99']
        out['throttle_cnt'] = d['throttle']['cnt']
        out['latency_p99'] = (out['int_latency_p99'] +
                              out['outbuf_latency_p99'] +
                              out['rtt_p99'])
        out['toppars_cnt'] = len(d['toppars'])
        out['produce_req'] = d['req']['Produce']

        brokers.append(out)

    tcollect = []
    tpcollect = ['leader', 'msgq_cnt', 'msgq_bytes',
                 'xmit_msgq_cnt', 'xmit_msgq_bytes',
                 'txmsgs', 'txbytes', 'msgs_inflight']

    topics = []
    toppars = []
    for t, d in js['topics'].items():

        tout = {'0time': dt, '1topic': t}
        for c in tcollect:
            tout[c] = d[c]
        tout['batchsize_p99'] = d['batchsize']['p99']
        tout['batchcnt_p99'] = d['batchcnt']['p99']

        for tp, d2 in d['partitions'].items():
            if d2['txmsgs'] == 0:
                continue

            tpout = {'0time': dt, '1partition': d2['partition']}

            for c in tpcollect:
                tpout[c] = d2[c]

            toppars.append(tpout)

        topics.append(tout)

    return [top], brokers, topics, toppars


class CsvWriter(object):
    def __init__(self, outpfx, name):
        self.f = open(f"{outpfx}_{name}.csv", "w")
        self.cnt = 0

    def write(self, d):
        od = OrderedDict(sorted(d.items()))
        if self.cnt == 0:
            # Write heading
            self.f.write(','.join(od.keys()) + '\n')

        self.f.write(','.join(map(str, od.values())) + '\n')
        self.cnt += 1

    def write_list(self, a_list_of_dicts):
        for d in a_list_of_dicts:
            self.write(d)


out = sys.argv[1]

w_top = CsvWriter(out, 'top')
w_brokers = CsvWriter(out, 'brokers')
w_topics = CsvWriter(out, 'topics')
w_toppars = CsvWriter(out, 'toppars')


for linenr, string in enumerate(sys.stdin):
    try:
        top, brokers, topics, toppars = parse(linenr, string)
    except Exception as e:
        print(f"SKIP {linenr+1}: {e}")
        continue

    w_top.write_list(top)
    w_brokers.write_list(brokers)
    w_topics.write_list(topics)
    w_toppars.write_list(toppars)
