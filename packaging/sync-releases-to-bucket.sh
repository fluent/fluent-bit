#!/bin/bash
set -eu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Simple script to "sync" releases from the legacy server to the release bucket.
# Can be run manually or scripted via CI - make sure to set up GPG & SSH keys if so.

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
fi

AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:?}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:?}
INPUT_BUCKET=${INPUT_BUCKET:-?}
OUTPUT_BUCKET=${OUTPUT_BUCKET:-$INPUT_BUCKET}
RELEASE_SERVER=${RELEASE_SERVER:-packages.fluentbit.io}
RELEASE_SERVER_PATH=${RELEASE_SERVER_PATH:-/var/www/apt.fluentbit.io}
RELEASE_SERVER_WINDOWS_PATH=${RELEASE_SERVER_WINDOWS_PATH:-/var/www/releases.fluentbit.io/releases}
RELEASE_SERVER_USERNAME=${RELEASE_SERVER_USERNAME:-$USER}
GPG_KEY=${GPG_KEY:?}
BASE_PATH=${BASE_PATH:-$SCRIPT_DIR/aws-release-sync}
# Rsync command info: https://explainshell.com/explain?cmd=rsync+-chavzP+--prune-empty-dirs
RSYNC_CMD=${RSYNC_CMD:-rsync -chavzP --prune-empty-dirs}
# Used to speed up rsync from server by specifying a particular release you want only downloaded.
# We still have to grab all of AWS to reconstruct.
SYNC_VERSION=${SYNC_VERSION:-}
# Run only segments of this script before exiting
# DOWNLOAD_ONLY - download from AWS and the server only
# DISABLE_UPLOAD - run everything except the final sync to $OUTPUT_BUCKET
MODE=${MODE:-}

# We download everything from AWS but only artefacts from the server.
# We then massage them into a common format ready to recreate the repository metadata from.
mkdir -p "$BASE_PATH"

# Download from S3 bucket
aws-cli s3 sync "s3://$BUCKET" "$BASE_PATH"
echo "AWS download complete"

# Grab Linux packages from the release server
if [[ -z "$SYNC_VERSION" ]]; then
    $RSYNC_CMD --include='*.rpm' --include='*.deb' --include='*.key' --include='*/' --exclude '*' \
        "$RELEASE_SERVER_USERNAME"@"$RELEASE_SERVER":"$RELEASE_SERVER_PATH"/ "$BASE_PATH"
else
    echo "Syncing only version: $SYNC_VERSION"
    $RSYNC_CMD --include="*$SYNC_VERSION*.rpm" --include="*$SYNC_VERSION*.deb" --include='*.key' --include='*/' --exclude '*' \
        "$RELEASE_SERVER_USERNAME"@"$RELEASE_SERVER":"$RELEASE_SERVER_PATH"/ "$BASE_PATH"
fi
echo "Server artefact download complete"

# Grab Windows packages
mkdir -p "$BASE_PATH"/windows
if [[ -z "$SYNC_VERSION" ]]; then
    $RSYNC_CMD --include='*win32.*' --include='*win64.*' --include='*/' --exclude '*' \
        "$RELEASE_SERVER_USERNAME"@"$RELEASE_SERVER":"$RELEASE_SERVER_WINDOWS_PATH"/ "$BASE_PATH"/windows
else
    $RSYNC_CMD --include="*$SYNC_VERSION*win32.*" --include="*$SYNC_VERSION*win64.*" --include='*/' --exclude '*' \
        "$RELEASE_SERVER_USERNAME"@"$RELEASE_SERVER":"$RELEASE_SERVER_WINDOWS_PATH"/ "$BASE_PATH"/windows
fi
echo "Windows package download complete"

# Generate checksums for all Windows releases
find "$BASE_PATH"/windows -type f -name "*win*.*" -exec sh -c 'cd "${1%/*}";sha256sum "${1##*/}" > "$1".sha256' _ {} \;
echo "Windows checksum creation complete"

# Now grab the repos we do not process to leave as-is
LEGACY_REPOS=( "debian/jessie"
                "debian/stretch" )
for LEGACY_REPO in "${LEGACY_REPOS[@]}"; do
    $RSYNC_CMD "$RELEASE_SERVER_USERNAME"@"$RELEASE_SERVER":"$RELEASE_SERVER_PATH"/"$LEGACY_REPO" "$BASE_PATH/$LEGACY_REPO"
done
echo "Legacy APT repository download complete"

if [[ "$MODE" == "DOWNLOAD_ONLY" ]]; then
    echo "Download only specified so skipping metadata construction and upload"
    exit 0
fi

# Remove duplicates for Yum repos and generally consolidate everything so RPMs are at
# the root of the repo rather than in architecture-specific subdirectories.
RPM_REPO_PATHS=("amazonlinux/2" "centos/7" "centos/8")
for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    echo "Updating $RPM_REPO"
    REPO_DIR=$( realpath -sm "$BASE_PATH/$RPM_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue
    find "$REPO_DIR" -name "*.rpm" -exec cp -fv {} "$REPO_DIR/" \;
    rm -rf "$REPO_DIR"/aarch64 "$REPO_DIR"/x86_64 "$REPO_DIR"/repodata
done
echo "YUM repository construction complete"

# For Aptly we need everything at the top-level to then add it.
# We only cover repos we have started managing from 1.9 onwards.
DEB_REPO_PATHS=( "debian/bullseye"
                    "debian/buster"
                    "ubuntu/xenial"
                    "ubuntu/bionic"
                    "ubuntu/focal"
                    "ubuntu/jammy"
                    "raspbian/buster"
                    "raspbian/bullseye" )
for DEB_REPO in "${DEB_REPO_PATHS[@]}"; do
    REPO_DIR=$(realpath -sm "$BASE_PATH/$DEB_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue
    CODENAME=${DEB_REPO##*/}

    find "$REPO_DIR" -name "*.deb" -exec cp -fv {} "$REPO_DIR/" \;
    rm -rf "$REPO_DIR"/pool "$REPO_DIR"/dists "${REPO_DIR:?}/$CODENAME"
done
echo "APT repository construction complete"

# Update metadata now - have to use Ubuntu 18.04 for 'createrepo' to be available
if ! command -v createrepo ; then
    echo "Unable to find createrepo"
    exit 1
fi

# This will overwrite all the metadata to then push back up to the bucket
"$SCRIPT_DIR/update-repos.sh" "$BASE_PATH"
echo "Repository metadata construction complete"

if [[ "$MODE" == "DISABLE_UPLOAD" ]]; then
    echo "Skipping upload as requested"
    exit 0
fi

# Now sync back up
aws-cli s3 sync "$BASE_PATH" "s3://$BUCKET"
echo "Release sync complete"
