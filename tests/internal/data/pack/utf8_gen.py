# Fluent Bit / Pack utf-8 samples to JSON
# =======================================

import os
import json
import msgpack

def gen_json(f):

    print f

    with io.open(f, 'rb') as raw:
        data = raw.read()

    out_mp = f[:-4] + ".mp"
    out_json = f[:-4] + ".json"

    # Write messagepack
    fmp = open(out_mp, 'w')
    fmp.write(msgpack.packb(data))
    fmp.close()

    fjson = open(out_json, 'w')
    fjson.write(json.dumps(data).encode('utf8'))
    fjson.close()

for fn in os.listdir('.'):
     if not os.path.isfile(fn):
         continue

     if fn.startswith('utf8_') and fn.endswith('.txt'):
         gen_json(fn)
