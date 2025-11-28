#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Simple helper script to run various code-analysis tools (sanitisers, coverage, etc.) and unit test using a simple helper container.
# Refer to https://github.com/lpenz/ghaction-cmake for more details: https://github.com/lpenz/ghaction-cmake#using-in-other-environments
TEST_PRESET=${TEST_PRESET:-coverage}

export SOURCE_DIR=${SOURCE_DIR:-$SCRIPT_DIR}
CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-docker}

# From the Dockerfile
FLB_CMAKE_OPTIONS=${FLB_CMAKE_OPTIONS:--DFLB_BACKTRACE=Off -DFLB_SHARED_LIB=Off -DFLB_DEBUG=On -DFLB_ALL=On -DFLB_EXAMPLES=Off -DFLB_TESTS_INTERNAL=On -DFLB_TESTS_RUNTIME=On}
ADDITIONAL_DEPS=${ADDITIONAL_DEPS:-libssl-dev libsasl2-dev pkg-config libsystemd-dev zlib1g-dev libpq-dev postgresql-server-dev-all flex bison libsnmp-dev libyaml-dev netcat}

# From the Unit Tests script
SKIP_TESTS=${SKIP_TESTS:-flb-rt-out_elasticsearch flb-it-network flb-it-fstore flb-rt-out_elasticsearch flb-rt-out_td flb-rt-out_forward flb-rt-in_disk flb-rt-in_proc}

SKIP=""
for skip in $SKIP_TESTS
do
    SKIP="$SKIP -DFLB_WITHOUT_${skip}=1"
done

# Check we have an actual Fluent Bit source directory
if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "ERROR: no SOURCE_DIR directory"
    exit 1
elif [[ ! -f "$SOURCE_DIR"/CMakeLists.txt ]]; then
    echo "ERROR: no CMakeLists.txt found in SOURCE_DIR"
    exit 1
fi

machine_id_file="$(mktemp)"
< /dev/urandom tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 > "${machine_id_file}"

cmake_version="${CMAKE_VERSION:-"3.31.6"}"
cmake_url="${CMAKE_URL:-"https://github.com/Kitware/CMake/releases/download"}"
cmake_home="/opt/cmake"

exit_code=0
# Run the action we want on it but using an in-container build directory to prevent various permissions errors and files locally
"$CONTAINER_RUNTIME" run --rm -t -w "/tmp/source" -v "${SOURCE_DIR}:/source:ro" \
    -v "${machine_id_file}:/etc/machine-id:ro" \
    -e INPUT_PRESET="$TEST_PRESET" \
    -e INPUT_DEPENDENCIES_DEBIAN="$ADDITIONAL_DEPS" \
    -e INPUT_CMAKEFLAGS="$FLB_CMAKE_OPTIONS $SKIP" \
    -e INPUT_PRE_COMMAND="cp -R /source /tmp" \
    -e INPUT_WORKING-DIRECTORY="/tmp/source" \
    lpenz/ghaction-cmake:0.19 \
    sh -c "\
        cmake_install_script=\"\$(mktemp --suffix '.sh')\" && \
        cmake_download_url=$(printf "%q" "${cmake_url}/v${cmake_version}/cmake-${cmake_version}")\"-linux-\$(uname -m).sh\" && \
        echo \"Downloading CMake: \${cmake_download_url} -> \${cmake_install_script}\" && \
        curl -jksSL -o \"\${cmake_install_script}\" \"\${cmake_download_url}\" && \
        mkdir -p $(printf "%q" "${cmake_home}") && \
        echo \"Installing CMake: \${cmake_install_script} -> \"$(printf "%q" "${cmake_home}") && \
        sh \"\${cmake_install_script}\" --skip-license --exclude-subdir --prefix=$(printf "%q" "${cmake_home}") && \
        rm -f \"\${cmake_install_script}\" && \
        export PATH=\"$(printf "%q" "${cmake_home}/bin"):\${PATH}\" && \
        cmake --version && \
        entrypoint" \
    || exit_code=$?

rm -f "${machine_id_file}"
exit "${exit_code}"
