#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
"""
It is used to append a .aot to a .wasm as a custom section.
The custom section name is "aot".

e.g.
$ python3 append_aot_to_wasm.py --wasm quicksort.wasm --aot quicksort.aot --output quicksort.aot.wasm
"""

import argparse
from pathlib import Path


def leb128_encode_uint(value: int) -> bytes:
    """
    encode unsigned int into a leb128 bytes
    """
    binary = []
    while value != 0:
        lower_7_bits = value & 0x7F
        value >>= 7

        if value != 0:
            current_byte = 0x80 | lower_7_bits
        else:
            current_byte = 0x00 | lower_7_bits

        binary.append(current_byte)

    return bytes(binary)


def leb128_decode_uint(binary: bytes) -> (int, int):
    """
    decode binary unsigned from a leb128 bytes
    """

    result = 0
    shift = 0
    for i, b in enumerate(binary):
        lower_7_bits = b & 0x7F
        result |= lower_7_bits << shift

        highest_bit = b & 0x80
        if not highest_bit:
            break

        shift += 7

    return i + 1, result


def is_aligned(n: int, alignment: int):
    return (n & (alignment - 1)) == 0


def align_up(n: int, alignment: int):
    return n + (alignment - 1) & ~(alignment - 1)


def present_as_vector(content: bytes) -> bytes:
    v_l = len(content)
    v_bin = leb128_encode_uint(v_l) if v_l else b"\x00"
    return v_bin + content


def calc_padding(
    alignment: int, name_bin_len: int, content_len: int, start_pos: int
) -> bytes:
    for padding in range(alignment * 2):
        padding_bin = present_as_vector(b"\x00" * padding)
        section_length = name_bin_len + len(padding_bin) + content_len
        section_length_bin = leb128_encode_uint(section_length)

        pos = start_pos + 1 + len(section_length_bin) + name_bin_len + len(padding_bin)
        if is_aligned(pos, alignment):
            return padding_bin


def build_content(content: bytes, pos: int, adding: bytes) -> (int, bytes):
    return pos + len(adding), content + adding


def create_custom_section_aligned(
    start_pos: int, name: str, content: bytes, alignment: int = 4
) -> bytes:
    """
        be sure the section_content starts at a X alignment position

          1B
        | \x00 | length | name vec | padding vec | content |
        ^                                        ^
        |                                        |
    start address                           aligned address
    """

    name_bin = present_as_vector(name.encode("ascii"))
    padding_bin = calc_padding(alignment, len(name_bin), len(content), start_pos)

    full_content_bin = b""
    pos = start_pos

    # custome section id 0
    pos, full_content_bin = build_content(full_content_bin, pos, b"\x00")

    # custom section length
    section_length = len(name_bin) + len(padding_bin) + len(content)
    section_length_bin = leb128_encode_uint(section_length)
    pos, full_content_bin = build_content(full_content_bin, pos, section_length_bin)

    # custom section name
    pos, full_content_bin = build_content(full_content_bin, pos, name_bin)

    # padding
    pos, full_content_bin = build_content(full_content_bin, pos, padding_bin)
    assert is_aligned(pos, alignment), f"{pos} is not aligned to {alignment}"

    print(f"append .aot @ offset {pos}(0x{pos:X})")
    _, full_content_bin = build_content(full_content_bin, pos, content)

    return full_content_bin


def main(wasm_file: str, aot_file: str, output: str) -> None:
    cwd = Path.cwd()
    wasm_file = cwd.joinpath(wasm_file).resolve()
    aot_file = cwd.joinpath(aot_file).resolve()
    output = cwd.joinpath(output).resolve()

    assert wasm_file.exists()
    assert aot_file.exists()
    output.unlink(missing_ok=True)

    # read aot content
    with open(aot_file, "rb") as f:
        aot_content = f.read()

    # append to .wasm
    with open(wasm_file, "rb") as f_in, open(output, "wb") as f_out:
        wasm_content = f_in.read(1024)
        while wasm_content:
            f_out.write(wasm_content)
            wasm_content = f_in.read(1024)

        f_out.write(create_custom_section_aligned(f_out.tell(), "aot", aot_content, 4))

    print(f"{wasm_file.name} + {aot_file.name} ==> {output}")


if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument("--wasm", help="a .wasm")
    argparse.add_argument("--aot", help="a .aot")
    argparse.add_argument("-o", "--output", help="the output, still be a .wasm")

    args = argparse.parse_args()
    main(args.wasm, args.aot, args.output)
