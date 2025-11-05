#!/usr/bin/env python3
#
# Copyright (C) 2024 Amazon Inc.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

"""
This tool corrects function names in call stacks based on the
instruction pointers.

When the AOT file is generated with excluded func-idx in the
`--call-stack-features` parameter, the function indexes are
incorrect (likely they're zero). This script uses instruction
pointers and the original WASM file to generate a call stack
file with the correct function indexes (or function names,
when available).

Example input (call_stack.txt) - note that `__imported_wasi_snapshot_preview1_fd_close`
had index 0, therefore it appears as a name in every line:
```
#00: 0x0505 - __imported_wasi_snapshot_preview1_fd_close
#01: 0x0309 - __imported_wasi_snapshot_preview1_fd_close
#02: 0x037c - __imported_wasi_snapshot_preview1_fd_close
#03: 0x03b2 - __imported_wasi_snapshot_preview1_fd_close
#04: 0x03e4 - __imported_wasi_snapshot_preview1_fd_close
#05: 0x02e6 - __imported_wasi_snapshot_preview1_fd_close
```

Conversion command:
```
python3 test-tools/ip2function/ip2function.py \
    --wasm-file opt-samp/tiny.wasm \
    call_stack.txt
```

Output:
```
#0: 0x0505 - abort
#1: 0x0309 - baz
#2: 0x037c - bar
#3: 0x03b2 - foo
#4: 0x03e4 - __original_main
#5: 0x02e6 - _start
```
"""

import argparse
import bisect
import os
import re
import subprocess
import sys

from typing import NamedTuple, Optional
from typing import TextIO
from pathlib import Path
import shutil


class FunctionInfo(NamedTuple):
    start_address: int
    idx: int
    name: Optional[str]

    def __str__(self) -> str:
        return self.name if self.name else f"$f{self.idx}"


def load_functions(wasm_objdump: Path, wasm_file: Path) -> list[FunctionInfo]:
    objdump_function_pattern = re.compile(
        r"^([0-9a-f]+)\sfunc\[(\d+)\](?:\s\<(.+)\>)?\:$"
    )

    def parse_objdump_function_line(
        line: str,
    ) -> Optional[FunctionInfo]:
        match = objdump_function_pattern.match(line.strip())
        return (
            FunctionInfo(int(match[1], 16), int(match[2]), match[3]) if match else None
        )

    p = subprocess.run(
        [wasm_objdump, "--disassemble", wasm_file],
        check=True,
        capture_output=True,
        text=True,
        universal_newlines=True,
    )

    return list(
        filter(
            None,
            (
                parse_objdump_function_line(line.strip())
                for line in p.stdout.split(os.linesep)
            ),
        )
    )


def parse_call_stack_file(
    functions: list[FunctionInfo], call_stack_file: TextIO, output_file: TextIO
) -> None:
    call_stack_line_pattern = re.compile(r"^(#\d+): (0x[0-9a-f]+) \- (\S+)$")
    for line in call_stack_file:
        match = call_stack_line_pattern.match(line.strip())
        if not match:
            output_file.write(line)
            continue
        index = match[1]
        address = match[2]

        func_pos = bisect.bisect_right(
            functions, int(address, 16), key=lambda x: x.start_address
        )
        if func_pos <= 0:
            raise ValueError(f"Cannot find function for address {address}")
        output_file.write(f"{index}: {address} - {functions[func_pos -1]}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="addr2line for wasm")
    parser.add_argument(
        "--wasm-objdump", type=Path, default="wasm-objdump", help="path to wasm objdump"
    )
    parser.add_argument(
        "--wasm-file", required=True, type=Path, help="path to wasm file"
    )
    parser.add_argument(
        "call_stack_file", type=argparse.FileType("r"), help="path to a call stack file"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="Output file path (default is stdout)",
    )

    args = parser.parse_args()

    wasm_objdump: Path = shutil.which(args.wasm_objdump)
    assert wasm_objdump is not None

    wasm_file: Path = args.wasm_file
    assert wasm_file.exists()

    parse_call_stack_file(
        load_functions(wasm_objdump, wasm_file), args.call_stack_file, args.output
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
