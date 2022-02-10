#!/bin/bash
set -eu

# Never rely on PWD so we can invoke from anywhere
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Allow us to specify in the caller or pass variables
FLB_BRANCH=${FLB_BRANCH:-}
FLB_PREFIX=${FLB_PREFIX:-}
FLB_VERSION=${FLB_VERSION:-}
FLB_DISTRO=${FLB_DISTRO:-}
FLB_OUT_DIR=${FLB_OUT_DIR:-}
FLB_TARGZ=${FLB_TARGZ:-}
FLB_NIGHTLY_BUILD=${FLB_NIGHTLY_BUILD:-}

while getopts "v:d:b:t:o:" option
do
        case "${option}"
        in
            v) FLB_VERSION=${OPTARG};;
            d) FLB_DISTRO=${OPTARG};;
            b) FLB_BRANCH=${OPTARG};;
            t) FLB_TARGZ=${OPTARG};;
            o) FLB_OUT_DIR=${OPTARG};;
            *) echo "Unknown option";;
        esac
done

if [ -z "$FLB_VERSION" ] || [ -z "$FLB_DISTRO" ]; then
    echo "$@"
    echo "Usage: build.sh  -v VERSION  -d DISTRO"
    echo "                 ^               ^    "
    echo "                 | 1.9.0         | ubuntu/20.04"
    exit 1
fi

if [ -z "$FLB_BRANCH" ]; then
    # The standard tags have a v prefix but we may want to build others
    if curl -sL --output /dev/null --head --fail "http://github.com/fluent/fluent-bit/archive/v$FLB_VERSION.zip" ; then
        FLB_PREFIX="v"
    fi
fi

# Prepare output directory
if [ -n "$FLB_OUT_DIR" ]; then
    out_dir=$FLB_OUT_DIR
else
    out_dir=$(date '+%Y-%m-%d-%H_%M_%S')
fi

volume="$SCRIPT_DIR/packages/$FLB_DISTRO/$FLB_VERSION/$out_dir/"
mkdir -p "$volume"

# Info
echo "FLB_PREFIX            => $FLB_PREFIX"
echo "FLB_VERSION           => $FLB_VERSION"
echo "FLB_DISTRO            => $FLB_DISTRO"
echo "FLB_SRC               => $FLB_TARGZ"
echo "FLB_OUT_DIR           => $FLB_OUT_DIR"

MAIN_IMAGE="flb-$FLB_VERSION-$FLB_DISTRO"

# We either have a specific Dockerfile in the distro directory or we have a generic multi-stage one for all
# of the same OS type:
# - ubuntu/Dockerfile
# - ubuntu/18.04/Dockerfile
# Use the specific one as an override for any special cases but try to keep the general multi-stage one.
# For the multistage ones, we pass in the base image to use.
#
IMAGE_CONTEXT_DIR="$SCRIPT_DIR/distros/$FLB_DISTRO"
FLB_ARG=""
if [[ ! -d "$SCRIPT_DIR/distros/$FLB_DISTRO" ]]; then
    IMAGE_CONTEXT_DIR="$SCRIPT_DIR/distros/${FLB_DISTRO%%/*}"
    FLB_ARG="--build-arg BASE_BUILDER=${FLB_DISTRO%%/*}-${FLB_DISTRO##*/}-base --target builder"
fi

if [[ ! -f "$IMAGE_CONTEXT_DIR/Dockerfile" ]]; then
    echo "Unable to find $IMAGE_CONTEXT_DIR/Dockerfile"
    exit 1
fi

echo "IMAGE_CONTEXT_DIR     => $IMAGE_CONTEXT_DIR"

# Create sources directory if it does not exist
mkdir -p "$IMAGE_CONTEXT_DIR/sources"

# Set tarball as an argument (./build.sh VERSION DISTRO/CODENAME -t something.tar.gz)
if [ -n "$FLB_TARGZ" ]; then
    # Check if we have a local tarball
    if [[ ! -f "$FLB_TARGZ" ]]; then
        echo "Unable to find tarball: $FLB_TARGZ"
        exit 1
    fi

    # Copy tarball
    cp "$FLB_TARGZ" "$IMAGE_CONTEXT_DIR/sources/"
    # Set build argument (ensure we strip off any path)
    FLB_ARG="$FLB_ARG --build-arg FLB_SRC=$(basename "$FLB_TARGZ")"
else
    # Check we have a valid remote source URL
    FLB_SOURCE_URL="http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip"
    if ! curl -sL --output /dev/null --head --fail "$FLB_SOURCE_URL" ; then
        echo "Unable to download source from URL:$FLB_SOURCE_URL "
        exit 1
    fi
fi

# The FLB_NIGHTLY_BUILD must not be empty so set to version if not defined
if [[ -z "$FLB_NIGHTLY_BUILD" ]]; then
    FLB_NIGHTLY_BUILD="$FLB_VERSION"
fi

# CMake configuration variables, override via environment rather than parameters
CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX:-/opt/td-agent-bit/}
FLB_TD=${FLB_TD:-On}

echo "CMAKE_INSTALL_PREFIX  => $CMAKE_INSTALL_PREFIX"
echo "FLB_TD                => $FLB_TD"
echo "FLB_ARG               => $FLB_ARG"
echo "FLB_NIGHTLY_BUILD     => $FLB_NIGHTLY_BUILD"

export DOCKER_BUILDKIT=1

# Build the main image - we do want word splitting
# shellcheck disable=SC2086
if ! docker build \
    --build-arg CMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    --build-arg FLB_TD="$FLB_TD" \
    --build-arg FLB_VERSION="$FLB_VERSION" \
    --build-arg FLB_PREFIX="$FLB_PREFIX" \
    --build-arg FLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    $FLB_ARG \
    -t "$MAIN_IMAGE" "$IMAGE_CONTEXT_DIR"
then
    echo "Error building main docker image $MAIN_IMAGE"
    exit 1
fi

# Compile and package
if ! docker run \
    -v "$volume":/output \
    "$MAIN_IMAGE"
then
    echo "Could not compile on image $MAIN_IMAGE"
    exit 1
fi

# Delete image on success
if [ -n "$(docker images -q "$MAIN_IMAGE")" ]; then
    docker rmi -f "$MAIN_IMAGE"
fi

echo
echo "Package(s) generated at: $volume"
echo
