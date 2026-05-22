#!/bin/bash
set -eux

# Used to update a Debian Apt repo, e.g. during a staging build or release process

# Where the base of all the repos is
BASE_PATH=${BASE_PATH:?}
if [[ ! -d "$BASE_PATH" ]]; then
    echo "ERROR: invalid base path: $BASE_PATH"
    exit 1
fi

# "debian/bookworm" "debian/bullseye" "debian/trixie" "ubuntu/xenial" "ubuntu/bionic" "ubuntu/focal" "ubuntu/jammy" "raspbian/bullseye"
DEB_REPO=${DEB_REPO:?}

# Set true to prevent signing
DISABLE_SIGNING=${DISABLE_SIGNING:-false}

REPO_DIR=$(realpath -sm "$BASE_PATH/$DEB_REPO" )
if [[ ! -d "$REPO_DIR" ]] ; then
    echo "ERROR: missing $REPO_DIR"
    exit 1
fi

CODENAME=${DEB_REPO##*/}
echo "Updating $DEB_REPO for $CODENAME"

# We use Aptly to create repos with a local temporary directory as the root.
# Once complete, we then move these to the output directory for upload.
# Based on https://github.com/spotify/debify/blob/master/debify.sh
APTLY_REPO_NAME="debify-$CODENAME"
APTLY_ROOTDIR=$(mktemp -d)
APTLY_CONFIG=$(mktemp)

# The origin and label fields seem to cover the base directory for the repo and codename.
# The docs seems to suggest these fields are optional and free-form: https://wiki.debian.org/DebianRepository/Format#Origin
# They are security checks to verify if they have changed so we match the legacy server.
APTLY_ORIGIN=". $CODENAME"
APTLY_LABEL=". $CODENAME"
if [[ "$DEB_REPO" == "debian/bullseye" ]]; then
    # For Bullseye, the legacy server had a slightly different setup we try to reproduce here
    APTLY_ORIGIN="bullseye bullseye"
    APTLY_LABEL="bullseye bullseye"
fi

cat << EOF > "$APTLY_CONFIG"
{
    "rootDir": "$APTLY_ROOTDIR/"
}
EOF
cat "$APTLY_CONFIG"

aptly -config="$APTLY_CONFIG" repo create \
    -component="main" \
    -distribution="$CODENAME" \
    "$APTLY_REPO_NAME"

# Check if any files to add
count=$(find "$REPO_DIR" -maxdepth 1 -type f -name "*.deb" | wc -l)
if [[ $count != 0 ]] ; then
    # Do not remove files as we need them from moving to staging-release
    aptly -config="$APTLY_CONFIG" repo add -force-replace "$APTLY_REPO_NAME" "$REPO_DIR/"
    aptly -config="$APTLY_CONFIG" repo show "$APTLY_REPO_NAME"

    if [[ "$DISABLE_SIGNING" != "true" ]]; then
        aptly -config="$APTLY_CONFIG" publish repo -gpg-key="$GPG_KEY" -origin="$APTLY_ORIGIN" -label="$APTLY_LABEL" "$APTLY_REPO_NAME"
    else
        aptly -config="$APTLY_CONFIG" publish repo --skip-signing -origin="$APTLY_ORIGIN" -label="$APTLY_LABEL" "$APTLY_REPO_NAME"
    fi

    rsync -av "$APTLY_ROOTDIR"/public/* "$REPO_DIR"
    # Remove unnecessary files
    rm -rf "$REPO_DIR/conf/" "$REPO_DIR/db/" "$APTLY_ROOTDIR" "$APTLY_CONFIG"
else
    echo "WARNING: no files to add in $DEB_REPO for $CODENAME"
fi
