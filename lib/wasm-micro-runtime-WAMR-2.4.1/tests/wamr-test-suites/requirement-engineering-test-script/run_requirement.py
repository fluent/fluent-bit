#!/usr/bin/python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import sys
import argparse
from typing import Dict, Tuple, List
import importlib
import inspect
import csv

REQUIREMENT_TESTS_DIR = "../../requirement-engineering"
SUBREQUIREMENT_DESCRIPTIONS = {}


# To use this empty function to do signature check
def expected_build_func_template(verbose: bool) -> None:
    pass


# To use this empty function to do signature check
# The actual implementation of the return value should has following information:
#
def expected_run_func_template(
    output_dir: str, subrequirement_ids: List[int]
) -> Dict[int, Dict[Tuple[str, str], bool]]:
    pass


def dynamic_import(requirement_dir: str):
    # Declare that we intend to modify the global variable
    global SUBREQUIREMENT_DESCRIPTIONS
    sys.path.append(requirement_dir)
    os.chdir(requirement_dir)

    try:
        build_module = importlib.import_module("build")
        build_function = getattr(build_module, "build")
    except AttributeError:
        raise ImportError("'build' function not found in the specified build.py file.")

    try:
        run_module = importlib.import_module("run")
        run_function = getattr(run_module, "run")
        SUBREQUIREMENT_DESCRIPTIONS = getattr(run_module, "SUBREQUIREMENT_DESCRIPTIONS")
    except AttributeError:
        raise ImportError(
            "'run' function or 'SUBREQUIREMENT_DESCRIPTIONS' not found in the specified run.py file."
        )

    # Do signature check
    expected_signature = inspect.signature(expected_build_func_template)
    actual_signature = inspect.signature(build_function)
    assert (
        actual_signature == expected_signature
    ), "The build function doesn't have the expected signature"

    expected_signature = inspect.signature(expected_run_func_template)
    actual_signature = inspect.signature(run_function)
    assert (
        actual_signature == expected_signature
    ), "The run function doesn't have the expected signature"

    # Check if the variable is a dictionary
    if not isinstance(SUBREQUIREMENT_DESCRIPTIONS, dict):
        raise TypeError("SUBREQUIREMENT_DESCRIPTIONS is not a dictionary")

    # Check the types of keys and values in the dictionary
    for key, value in SUBREQUIREMENT_DESCRIPTIONS.items():
        if not isinstance(key, int):
            raise TypeError("Key in SUBREQUIREMENT_DESCRIPTIONS is not an int")
        if not (
            isinstance(value, tuple)
            and len(value) == 2
            and all(isinstance(elem, str) for elem in value)
        ):
            raise TypeError(
                "Value in SUBREQUIREMENT_DESCRIPTIONS is not a Tuple[str, str]"
            )

    return build_function, run_function


def cmd_line_summary(
    requirement_name: str, result_dict: dict, subrequirement_descriptions: dict
):
    # command line summary
    total, total_pass_nums, total_fail_nums = 0, 0, 0
    print(f"\n============ Start: Summary of {requirement_name} test ============")
    for subrequirement_id in result_dict.keys():
        sub_total = len(result_dict[subrequirement_id])
        pass_nums = len(
            [_ for _, result in result_dict[subrequirement_id].items() if result]
        )
        fail_nums = len(
            [_ for _, result in result_dict[subrequirement_id].items() if not result]
        )
        issue_number, subrequirement_description = subrequirement_descriptions.get(
            subrequirement_id, ""
        )

        print(f"\nTest Sub-requirement id: {subrequirement_id}")
        print(f"Issue Number: {issue_number}")
        print(f"Sub-requirement description: {subrequirement_description}")
        print(f"Number of test cases: {sub_total}")
        print(f"Pass: {pass_nums}")
        print(f"Fail: {fail_nums}\n")
        print(
            "----------------------------------------------------------------------------"
        )
        total += sub_total
        total_pass_nums += pass_nums
        total_fail_nums += fail_nums

    print(f"\nTotal Number of test cases: {total}")
    print(f"Pass: {total_pass_nums}")
    print(f"Fail: {total_fail_nums}\n")

    print(f"============= End: Summary of {requirement_name} test =============\n")


def generate_report(output_filename: str, result_dict: dict):
    # create a list of column names
    column_names = [
        "subrequirement id",
        "issue number",
        "subrequirement description",
        "running mode",
        "test case name",
        "test case description",
        "test case executing result",
    ]

    # open the output file in write mode
    with open(output_filename + ".csv", "w") as output_file:
        # create a csv writer object
        csv_writer = csv.writer(output_file)
        # write the column names as the first row
        csv_writer.writerow(column_names)
        # loop through the result_dict
        for subrequirement_id, test_cases in result_dict.items():
            # get the subrequirement description from the subrequirement_descriptions dict
            issue_number, subrequirement_description = SUBREQUIREMENT_DESCRIPTIONS.get(
                subrequirement_id, ""
            )
            # loop through the test cases
            for test_case, result in test_cases.items():
                # unpack the test case name and description from the tuple
                test_case_name, test_case_description = test_case
                # convert the result to pass or fail
                result = "pass" if result else "fail"
                # create a list of values for the current row
                row_values = [
                    subrequirement_id,
                    issue_number,
                    subrequirement_description,
                    "AOT",
                    test_case_name,
                    test_case_description,
                    result,
                ]
                # write the row values to the output file
                csv_writer.writerow(row_values)


def run_requirement(
    requirement_name: str, output_dir: str, subrequirement_ids: List[int]
):
    requirement_dir = os.path.join(REQUIREMENT_TESTS_DIR, requirement_name)
    if not os.path.isdir(requirement_dir):
        print(f"No such requirement in directory {requirement_dir} exists")
        sys.exit(1)

    output_path = os.path.join(output_dir, requirement_name)

    build_requirement_func, run_requirement_func = dynamic_import(requirement_dir)

    build_requirement_func(verbose=False)
    result_dict = run_requirement_func(output_path, subrequirement_ids)

    cmd_line_summary(requirement_name, result_dict, SUBREQUIREMENT_DESCRIPTIONS)
    generate_report(output_path, result_dict)


def main():
    parser = argparse.ArgumentParser(description="Process command line options.")

    # Define the '-o' option for output directory
    parser.add_argument(
        "-o", "--output_directory", required=True, help="Report output directory"
    )

    # Define the '-r' option for requirement name
    parser.add_argument(
        "-r", "--requirement_name", required=True, help="Requirement name"
    )

    # Define the subrequirement IDs as a list of integers
    parser.add_argument(
        "subrequirement_ids", nargs="*", type=int, help="Subrequirement IDs (optional)"
    )

    # Parse the arguments
    args = parser.parse_args()

    run_requirement(
        args.requirement_name, args.output_directory, list(args.subrequirement_ids)
    )


if __name__ == "__main__":
    main()
