# Fluent Bit / Pack mixed samples to JSON
# =======================================
# This script generate the JSON formatted strings for the mixed_ABC.txt samples.

import os
import json
import msgpack


def gen_json(f):
    # Open the input file in text mode with UTF-8 encoding
    with open(f, 'r', encoding='utf-8') as raw:
        data = raw.read()

    # Define output filenames
    base_name = os.path.splitext(f)[0]
    out_mp = base_name + ".mp"
    out_json = base_name + ".json"

    # Write MessagePack-encoded data in binary mode
    with open(out_mp, 'wb') as fmp:
        fmp.write(msgpack.packb(data))

    # Write JSON-encoded data in text mode
    with open(out_json, 'w', encoding='utf-8') as fjson:
        fjson.write(json.dumps(data))

for fn in os.listdir('.'):
     if not os.path.isfile(fn):
         continue

     if fn.startswith('mixed_') and fn.endswith('.txt'):
         gen_json(fn)
