#!/usr/bin/env bash

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

readonly WORK_DIR=$PWD
readonly WAMR_DIR=${WORK_DIR}/../../..
readonly DST_COV_FILE=$1
readonly SRC_COV_DIR=$2
readonly SRC_TEMP_COV_FILE=wamr_temp.lcov
readonly SRC_COV_FILE=wamr.lcov

# get dest folder
dir=$(dirname ${DST_COV_FILE})
pushd ${dir} > /dev/null 2>&1
readonly DST_COV_DIR=${PWD}
popd > /dev/null 2>&1

if [[ ! -d ${SRC_COV_DIR} ]]; then
    echo "${SRC_COV_DIR} doesn't exist, ignore code coverage collection"
    exit
fi

echo "Start to collect code coverage of ${SRC_COV_DIR} .."

pushd ${SRC_COV_DIR} > /dev/null 2>&1

# collect all code coverage data
lcov -q -o ${SRC_TEMP_COV_FILE} -c -d . --rc lcov_branch_coverage=1
# extract code coverage data of WAMR source files
lcov -q -r ${SRC_TEMP_COV_FILE} -o ${SRC_TEMP_COV_FILE} \
     -rc lcov_branch_coverage=1 \
     "*/usr/*" "*/_deps/*" "*/deps/*" "*/tests/unit/*" \
     "*/llvm/include/*" "*/include/llvm/*" "*/samples/*" \
    "*/test-tools/*" "*/tests/standalone/*" "*/tests/*"

if [[ -s ${SRC_TEMP_COV_FILE} ]]; then
    if [[ -s ${DST_COV_FILE} ]]; then
        # merge code coverage data
        lcov --rc lcov_branch_coverage=1 \
            --add-tracefile ${SRC_TEMP_COV_FILE} \
            -a ${DST_COV_FILE} -o ${SRC_COV_FILE}
        # backup the original lcov file
        cp -a ${DST_COV_FILE} "${DST_COV_FILE}.orig"
        # replace the lcov file
        cp -a ${SRC_COV_FILE} ${DST_COV_FILE}
        echo "Code coverage file ${DST_COV_FILE} was appended"
    else
        cp -a ${SRC_TEMP_COV_FILE} ${SRC_COV_FILE}
        cp -a ${SRC_COV_FILE} ${DST_COV_FILE}
        echo "Code coverage file ${DST_COV_FILE} was generated"
    fi

    # get ignored prefix path
    dir=$(dirname ${WAMR_DIR}/../..)
    pushd ${dir} > /dev/null 2>&1
    prefix_full_path=${PWD}
    popd > /dev/null 2>&1

    # generate html output for merged code coverage data
    rm -fr ${DST_COV_DIR}/wamr-lcov
    genhtml -q -t "WAMR Code Coverage" \
        --rc lcov_branch_coverage=1 --prefix=${prefix_full_path} \
        -o ${DST_COV_DIR}/wamr-lcov \
        ${DST_COV_FILE}

    cd ${DST_COV_DIR}
    rm -f wamr-lcov.zip
    zip -r -q -o wamr-lcov.zip wamr-lcov
    rm -fr wamr-lcov

    echo "Code coverage html ${DST_COV_DIR}/wamr-lcov.zip was generated"
else
    echo "generate code coverage html failed"
fi

echo ""

popd > /dev/null 2>&1
