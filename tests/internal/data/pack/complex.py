# Fluent Bit / Pack complex samples to MP
# =======================================
# This script generate the mp formatted strings for the complex_ABC.txt samples.

import os
import json
import msgpack

def gen_mp(f):
    raw = open(f, 'r')
    data = json.load(raw)
    raw.close()

    out_mp = f[:-5] + ".mp"

    # Write messagepack
    fmp = open(out_mp, 'w')
    fmp.write(msgpack.packb(data, use_bin_type=True))
    fmp.close()


def gen_from_mixed(f):
    raw = open(f, 'r')
    data = raw.read().decode('utf-8')
    raw.close()

    data = {u'foo': data}

    out_json = "complex_" + f[:-4] + ".json"
    out_mp = "complex_" + f[:-4] + ".mp"

    # Write messagepack
    fmp = open(out_mp, 'w')
    fmp.write(msgpack.packb(data, use_bin_type=True))
    fmp.close()

    # Write messagepack
    fmp = open(out_json, 'w')
    fmp.write(json.dumps(data, separators=(',', ':')))
    fmp.close()

for fn in os.listdir('.'):
    if not os.path.isfile(fn):
        continue
    
    if fn.startswith('complex_') and fn.endswith('.json'):
        gen_mp(fn)

    if fn.startswith('mixed_') and fn.endswith('.txt'):
        gen_from_mixed(fn)
