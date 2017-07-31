# Fluent Bit / Pack mixed samples to JSON
# =======================================
# This script generate the JSON formatted strings for the mixed_ABC.txt samples.

import os
import json
import msgpack

def gen_json(f):
    raw = open(f, 'r')
    data = raw.read()
    raw.close()

    out_mp = f[:-4] + ".mp"
    out_json = f[:-4] + ".json"

    # Write messagepack
    fmp = open(out_mp, 'w')
    fmp.write(msgpack.packb(data))
    fmp.close()

    fjson = open(out_json, 'w')
    fjson.write(json.dumps(data))
    fjson.close()

for fn in os.listdir('.'):
     if not os.path.isfile(fn):
         continue

     if fn.startswith('mixed_') and fn.endswith('.txt'):
         gen_json(fn)
