#!/bin/bash

set -ex

PROJECT_NAME=jansson

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

if [[ ! -d /tmp/ossfuzz/projects/${PROJECT_NAME} ]]
then
    echo "Could not find the ${PROJECT_NAME} project in ossfuzz"

    # Exit with a success code while the jansson project is not expected to exist
    # on oss-fuzz.
    exit 0
fi

# Work out which repo to clone from, inside Docker
if [[ ${TRAVIS_PULL_REQUEST} != "false" ]]
then
    # Pull-request branch
    REPO=${TRAVIS_PULL_REQUEST_SLUG}
    BRANCH=${TRAVIS_PULL_REQUEST_BRANCH}
else
    # Push build.
    REPO=${TRAVIS_REPO_SLUG}
    BRANCH=${TRAVIS_BRANCH}
fi

# Modify the oss-fuzz Dockerfile so that we're checking out the current branch on travis.
sed -i "s@https://github.com/akheron/jansson.git@-b ${BRANCH} https://github.com/${REPO}.git@" /tmp/ossfuzz/projects/${PROJECT_NAME}/Dockerfile

# Try and build the fuzzers
pushd /tmp/ossfuzz
python infra/helper.py build_image --pull ${PROJECT_NAME}
python infra/helper.py build_fuzzers ${PROJECT_NAME}
popd
