#!/bin/bash
# Used during the release process to automatically pull the tagged build from AppVeyor
set -eux

TAG=${TAG:?}
URL=${URL:-https://ci.appveyor.com/api}
PROJECT_SLUG=${PROJECT_SLUG:-fluent/fluent-bit-2e87g}
OUTPUT_DIR=${OUTPUT_DIR:-$PWD}

# Search the history for the version built using our tag.
# Ensure we only have one version selected - the first is the latest.
APPVEYOR_BUILD_VERSION=$(curl -sSfL --header "Content-type: application/json" "$URL/projects/$PROJECT_SLUG/history?recordsNumber=100"|\
    jq -cr "first(.builds[]|select(.isTag)|select(.tag == \"$TAG\")).version")
APPVEYOR_BUILD_INFO=$(curl -sSfL --header "Content-type: application/json" "$URL/projects/$PROJECT_SLUG/build/${APPVEYOR_BUILD_VERSION}")

# Assuming two jobs - Win32/64
JOB_ID1=$(echo "$APPVEYOR_BUILD_INFO"| jq -cr .build.jobs[0].jobId)
JOB_ID2=$(echo "$APPVEYOR_BUILD_INFO"| jq -cr .build.jobs[1].jobId)

ARTIFACTS_JOB1=$(curl -sSfL --header "Content-type: application/json" "$URL/buildjobs/${JOB_ID1}/artifacts")
ARTIFACTS_JOB2=$(curl -sSfL --header "Content-type: application/json" "$URL/buildjobs/${JOB_ID2}/artifacts")

# Assuming two artefacts per job - fluent-bit (no td-agent-bit) zip/exe
JOB1_FILE1=$(echo "$ARTIFACTS_JOB1"| jq -cr .[0].fileName)
JOB1_FILE2=$(echo "$ARTIFACTS_JOB1"| jq -cr .[1].fileName)
JOB2_FILE1=$(echo "$ARTIFACTS_JOB2"| jq -cr .[0].fileName)
JOB2_FILE2=$(echo "$ARTIFACTS_JOB2"| jq -cr .[1].fileName)

# Download all the artefacts now
mkdir -p "$OUTPUT_DIR"
pushd "$OUTPUT_DIR"
curl -sSfLO "$URL/buildjobs/${JOB_ID1}/artifacts/$JOB1_FILE1"
curl -sSfLO "$URL/buildjobs/${JOB_ID1}/artifacts/$JOB1_FILE2"
curl -sSfLO "$URL/buildjobs/${JOB_ID2}/artifacts/$JOB2_FILE1"
curl -sSfLO "$URL/buildjobs/${JOB_ID2}/artifacts/$JOB2_FILE2"
popd
