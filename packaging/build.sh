#!/bin/sh

# Never rely on PWD
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

FLB_BRANCH=""
FLB_PREFIX=""
FLB_VERSION=""
FLB_DISTRO=""

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
    echo "                 | 1.3.0         | ubuntu/18.04"
    exit 1
fi

if [ -z "$FLB_BRANCH" ]; then
    FLB_PREFIX="v"
fi

# Validate 'Base Docker' image used to build the package
FLB_BASE=flb-build-base-$FLB_DISTRO

if [ -f "$SCRIPT_DIR/distros/$FLB_DISTRO/Dockerfile.base" ]; then
    if [ -z "$(docker images -q "$FLB_BASE")" ]; then
        # Base image not found, build it
        echo "Base Docker image $FLB_BASE not found"
        if ! docker build --no-cache \
            -t "$FLB_BASE" \
            -f "$SCRIPT_DIR/distros/$FLB_DISTRO/Dockerfile.base" \
            distros/"$FLB_DISTRO"/
        then
            echo "Error building base docker image"
            exit 1
        fi
    else
        echo "Base Docker image $FLB_BASE found, using cached image"
    fi
else
    echo "Using multistage builder"
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
echo "FLB_PREFIX  => $FLB_PREFIX"
echo "FLB_VERSION => $FLB_VERSION"
echo "FLB_DISTRO  => $FLB_DISTRO"
echo "FLB_SRC     => $FLB_TARGZ"

MAIN_IMAGE="flb-$FLB_VERSION-$FLB_DISTRO"
if [ -n "$(docker images -q "$MAIN_IMAGE")" ]; then
    echo "Deleting OLD image $MAIN_IMAGE"
    docker rmi -f "$MAIN_IMAGE"
fi

# Set tarball as an argument (./build.sh VERSION DISTRO/CODENAME -t something.tar.gz)
if [ -n "$FLB_TARGZ" ]; then
    # Create sources directory if it don't exists
    if [ ! -d "distros/$FLB_DISTRO/sources" ]; then
        mkdir "distros/$FLB_DISTRO/sources"
    fi

    # Set build argument and copy tarball
    FLB_ARG="--build-arg FLB_SRC=$FLB_TARGZ"
    cp "$FLB_TARGZ" "distros/$FLB_DISTRO/sources/"
fi

# Build the main image
if ! docker build \
    --no-cache \
    --build-arg FLB_VERSION="$FLB_VERSION" \
    --build-arg FLB_PREFIX=$FLB_PREFIX \
    "$FLB_ARG" \
    -t "$MAIN_IMAGE" "distros/$FLB_DISTRO"
then
    echo "Error building main docker image $MAIN_IMAGE"
    exit 1
fi

# Compile and package
if ! docker run \
       -e FLB_PREFIX=$FLB_PREFIX \
       -e FLB_VERSION="$FLB_VERSION" \
       -e FLB_SRC="$FLB_TARGZ" \
       -v "$volume":/output \
       "$MAIN_IMAGE"
then
    echo "Could not compile on image $MAIN_IMAGE"
    exit 1
fi

# Delete temporal Build image
if [ -n "$(docker images -q "$MAIN_IMAGE")" ]; then
    docker rmi -f "$MAIN_IMAGE"
fi

echo
echo "Package(s) generated at: $volume"
echo
