#!/usr/bin/python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import argparse
from typing import List, Dict, Tuple
import json

WORK_DIR = os.getcwd()
WAMR_DIR = os.path.join(WORK_DIR, "../../..")
IWASM_CMD = os.path.join(
    WORK_DIR, "../../../product-mini/platforms/linux/build/iwasm")
WAMRC_CMD = os.path.join(WORK_DIR, "../../../wamr-compiler/build/wamrc")

SUBREQUIREMENT_DESCRIPTIONS = {
    1: ("633", "Modify existing opcodes to conform to the semantics of the GC proposal when needed."),
    2: ("634", "Supporting new GC opcodes(semantics of GC MVP proposal spec)."),
    3: ("635", "Supporting new GC opcode(semantics of Binaryen GC spec)."),
}


def test_subrequirement(id: int) -> Dict[Tuple[str, str], bool]:
    print(f"\n============> test gc aot requirement: {id}")

    test_cases = {}
    result = {}

    with open('test_cases.json') as config_file:
        config = json.load(config_file)
        for req in config["sub-requirements"]:
            if req['req_id'] == id:
                test_cases = req['cases']
                break

    for case in test_cases:
        print(case)
        print(f"{case['name']}.aot")
        exit_status = os.system(
            f"python runtest.py --aot --wast2wasm spec/interpreter/wasm --interpreter {IWASM_CMD} --aot-compiler {WAMRC_CMD} --gc wasm-apps/{case['name']}.wast"
        )

        if exit_status == 0:
            result[case['name'], case['description']] = True
        else:
            result[case['name'], case['description']] = False

    return result


def run(
    output_dir: str, subrequirement_ids: List[int]
) -> Dict[int, Dict[Tuple[str, str], bool]]:
    # key: value -> subrequirement id: dict[tuple(test_case_name, test_case_description), is_success]
    result_dict: Dict[int, Dict[Tuple[str, str], bool]] = {}

    # Default run all subrequirement
    if not subrequirement_ids:
        subrequirement_ids = [1, 2, 3]

    for subrequirement_id in subrequirement_ids:
        if subrequirement_id not in SUBREQUIREMENT_DESCRIPTIONS.keys():
            print(
                f"Subrequirement id invalid! It should be a value in {[_ for _ in SUBREQUIREMENT_DESCRIPTIONS.keys()]}"
            )
            continue
        result_dict[subrequirement_id] = test_subrequirement(subrequirement_id)

    return result_dict


if __name__ == "__main__":
    print("============> test GC AOT")

    # Create the parser
    parser = argparse.ArgumentParser(
        description="A script to process sub-requirement ids, run corresponding test cases, and compile wamrc, iwasm if requested."
    )

    # The argparse module handles -h and --help by default, no needs to add it
    # Add an output option `-o` as a flag that, when specified, sets the variable to True
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        required=False,
        help="Specify the output file name. If provided, the script will write the results to <file name>.csv",
    )

    # Add positional arguments for integers
    parser.add_argument(
        "integers",
        metavar="N",
        type=int,
        nargs="*",
        help="an integer for the sub-requirement ids",
    )
    # Parse arguments
    args = parser.parse_args()

    run(args.output, args.integers)
