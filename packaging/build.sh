#!/bin/bash
# Build a specific Linux target using the local source code via a container image
set -eux

# Never rely on PWD so we can invoke from anywhere
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Allow us to specify in the caller or pass variables
FLB_DISTRO=${FLB_DISTRO:-}
FLB_OUT_DIR=${FLB_OUT_DIR:-}
FLB_NIGHTLY_BUILD=${FLB_NIGHTLY_BUILD:-}
FLB_JEMALLOC=${FLB_JEMALLOC:-On}
DOCKER=${FLB_DOCKER_CLI:-docker}

# Use this to pass special arguments to docker build
FLB_ARG=${FLB_ARG:-}

while getopts "v:d:b:t:o:" option
do
        case "${option}"
        in
            d) FLB_DISTRO=${OPTARG};;
            o) FLB_OUT_DIR=${OPTARG};;
            *) echo "Unknown option";;
        esac
done

if [ -z "$FLB_DISTRO" ]; then
    echo "$@"
    echo "Usage: build.sh -d DISTRO"
    echo "                 ^    "
    echo "                 | ubuntu/20.04"
    exit 1
fi

# Prepare output directory
if [ -n "$FLB_OUT_DIR" ]; then
    out_dir=$FLB_OUT_DIR
else
    out_dir=$(date '+%Y-%m-%d-%H_%M_%S')
fi

volume="$SCRIPT_DIR/packages/$FLB_DISTRO/$out_dir/"
mkdir -p "$volume"

# Info
echo "FLB_DISTRO            => $FLB_DISTRO"
echo "FLB_OUT_DIR           => $FLB_OUT_DIR"

MAIN_IMAGE="flb-$FLB_DISTRO"

# We either have a specific Dockerfile in the distro directory or we have a generic multi-stage one for all
# of the same OS type:
# - ubuntu/Dockerfile
# - ubuntu/18.04/Dockerfile
# Use the specific one as an override for any special cases but try to keep the general multi-stage one.
# For the multistage ones, we pass in the base image to use.
#
IMAGE_CONTEXT_DIR="$SCRIPT_DIR/distros/$FLB_DISTRO"
if [[ ! -d "$SCRIPT_DIR/distros/$FLB_DISTRO" ]]; then
    IMAGE_CONTEXT_DIR="$SCRIPT_DIR/distros/${FLB_DISTRO%%/*}"
    FLB_ARG="$FLB_ARG --build-arg BASE_BUILDER=${FLB_DISTRO%%/*}-${FLB_DISTRO##*/}-base --target builder"
fi

if [[ ! -f "$IMAGE_CONTEXT_DIR/Dockerfile" ]]; then
    echo "Unable to find $IMAGE_CONTEXT_DIR/Dockerfile"
    exit 1
fi

# CMake configuration variables, override via environment rather than parameters
CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX:-/opt/fluent-bit/}
# This is required to ensure we set the defaults to off for 1.9 builds
FLB_TD=${FLB_TD:-Off}
# This is provided for simplifying the build pipeline
FLB_UNICODE_ENCODER=${FLB_UNICODE_ENCODER:-On}

if [ "${FLB_DISTRO}" = "centos/6" ] || [ "${FLB_DISTRO}" = "centos/7" ] ||
       [ "${FLB_DISTRO}" = "centos/7.arm64v8" ]; then
    FLB_UNICODE_ENCODER=Off
fi

echo "IMAGE_CONTEXT_DIR     => $IMAGE_CONTEXT_DIR"
echo "CMAKE_INSTALL_PREFIX  => $CMAKE_INSTALL_PREFIX"
echo "FLB_NIGHTLY_BUILD     => $FLB_NIGHTLY_BUILD"
echo "FLB_JEMALLOC          => $FLB_JEMALLOC"
echo "FLB_UNICODE_ENCODER   => $FLB_UNICODE_ENCODER"

if [ "${DOCKER}" = "docker" ]; then
    export DOCKER_BUILDKIT=1
else
    export DOCKER_BUILDKIT=0
fi

# Build the main image - we do want word splitting
# shellcheck disable=SC2086
if ! ${DOCKER} build \
    --build-arg CMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    --build-arg FLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    --build-arg FLB_JEMALLOC="$FLB_JEMALLOC" \
    --build-arg FLB_TD="$FLB_TD" \
    --build-arg FLB_UNICODE_ENCODER="$FLB_UNICODE_ENCODER" \
    $FLB_ARG \
    -t "$MAIN_IMAGE" \
    -f "$IMAGE_CONTEXT_DIR/Dockerfile" \
    "$SCRIPT_DIR/.."
then
    echo "Error building main docker image $MAIN_IMAGE"
    exit 1
fi

# Compile and package
if ! ${DOCKER} run \
    -v "$volume":/output \
    "$MAIN_IMAGE"
then
    echo "Could not compile using image $MAIN_IMAGE"
    exit 1
fi

echo
echo "Package(s) generated at: $volume"
echo
