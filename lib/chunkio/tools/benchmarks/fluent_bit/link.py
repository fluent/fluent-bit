"""Relink identical Fluent Bit objects with two different ChunkIO archives."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--base-library', type=Path, required=True)
parser.add_argument('--head-library', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
observer = output / 'observer.o'
subprocess.run(['cc', '-O2', '-c', str(Path(__file__).with_name('observer.c')),
                '-o', str(observer)], check=True)
command = shlex.split((args.build / 'src/CMakeFiles/fluent-bit-bin.dir/link.txt').read_text())
library = '../library/libchunkio-static.a'
assert command.count(library) == 1, 'Expected exactly one ChunkIO archive in link command'
for variant, archive in [('base', args.base_library), ('head', args.head_library)]:
    link = command.copy()
    link[link.index('-o') + 1] = str(output / ('fluent-bit-' + variant))
    link[link.index(library)] = str(archive.resolve())
    link.append(str(observer))
    for symbol in ['cio_file_native_remap', 'cio_file_native_resize',
                   'cio_file_native_map', 'flb_input_log_append_records']:
        link.append('-Wl,--wrap=' + symbol)
    subprocess.run(link, cwd=args.build / 'src', check=True)
    (output / ('link-' + variant + '.json')).write_text(json.dumps(link, indent=2))
