# Fluent Bit / Pack utf-8 samples to JSON
# =======================================

import os
import json
import msgpack

def gen_json(f):
    print(f)

    with open(f, 'rb') as raw:
        data = raw.read()

    out_mp = f"{os.path.splitext(f)[0]}.mp"
    out_json = f"{os.path.splitext(f)[0]}.json"

    # Decode input bytes to a string
    try:
        decoded_data = data.decode('utf-8')
    except UnicodeDecodeError as e:
        print(f"Error: Unable to decode file {f} as UTF-8: {e}")
        return

    # Write messagepack
    with open(out_mp, 'wb') as fmp:
        fmp.write(msgpack.packb(decoded_data))

    # Write JSON with properly encoded Unicode escape sequences
    with open(out_json, 'w', encoding='utf-8') as fjson:
        # Use json.dumps with ensure_ascii=True for \uXXXX escape sequences
        escaped_data = json.dumps(decoded_data, ensure_ascii=True)
        fjson.write(escaped_data)

for fn in os.listdir('.'):
    if not os.path.isfile(fn):
        continue

    if fn.startswith('utf8_') and fn.endswith('.txt'):
        gen_json(fn)
