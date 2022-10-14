#!/bin/bash
set -eux

# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$1}
if [[ ! -d "$BASE_PATH" ]]; then
    echo "Invalid base path: $BASE_PATH"
    exit 1
fi

# Set true to prevent signing
DISABLE_SIGNING=${DISABLE_SIGNING:-false}
if [[ "$DISABLE_SIGNING" != "true" ]]; then
    echo "RPM signing configuration"
    rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
fi

# Handle Ubuntu 18/22 differences - no support on Ubuntu 20
CREATE_REPO_CMD=${CREATE_REPO_CMD:-}

# Assume if set we want to use it
if [[ -n "$CREATE_REPO_CMD" ]]; then
    echo "Using $CREATE_REPO_CMD"
elif command -v createrepo &> /dev/null; then
    echo "Found createrepo"
    CREATE_REPO_CMD="createrepo -dvp"
elif command -v createrepo_c &> /dev/null; then
    echo "Found createrepo_c"
    CREATE_REPO_CMD="createrepo_c -dvp"
else
    echo "Unable to find a command equivalent to createrepo"
    exit 1
fi

RPM_REPO_PATHS=("amazonlinux/2" "amazonlinux/2022" "centos/7" "centos/8" "centos/9")

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    echo "Updating $RPM_REPO"
    REPO_DIR=$( realpath -sm "$BASE_PATH/$RPM_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue

    if [[ "$DISABLE_SIGNING" != "true" ]]; then
        # Sign all RPMs created for this target, cover both fluent-bit and legacy packages for 1.9 branch
        find "$REPO_DIR" -name "*-bit-*.rpm" -exec rpm --define "_gpg_name $GPG_KEY" --addsign {} \;
    fi
    # Create full metadata for all RPMs in the directory
    "$CREATE_REPO_CMD" "$REPO_DIR"

    # Set up repo info
    if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
        # Create top-level file so replace path separator with dash
        # centos/8 --> centos-8.repo
        # This way we make sure not to have a mixed repo or overwrite files for each target.
        REPO_TYPE=${RPM_REPO/\//-}
        echo "Setting up $BASE_PATH/$REPO_TYPE.repo"
        cat << EOF > "$BASE_PATH/$REPO_TYPE.repo"
[Fluent-Bit]
name=Fluent Bit Packages - $REPO_TYPE - \$basearch
baseurl=https://$AWS_S3_BUCKET.s3.amazonaws.com/$RPM_REPO/
enabled=1
gpgkey=https://$AWS_S3_BUCKET.s3.amazonaws.com/fluentbit.key
gpgcheck=1
repo_gpgcheck=1
EOF
    fi
done

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
    echo "Updating $DEB_REPO for $CODENAME"

    # We use Aptly to create repos with a local temporary directory as the root.
    # Once complete, we then move these to the output directory for upload.
    # Based on https://github.com/spotify/debify/blob/master/debify.sh
    APTLY_REPO_NAME="debify-$CODENAME"
    APTLY_ROOTDIR=$(mktemp -d)
    APTLY_CONFIG=$(mktemp)

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
    else
        echo "No files to add in $DEB_REPO for $CODENAME"
    fi
    aptly -config="$APTLY_CONFIG" repo show "$APTLY_REPO_NAME"
    if [[ "$DISABLE_SIGNING" != "true" ]]; then
        aptly -config="$APTLY_CONFIG" publish repo -gpg-key="$GPG_KEY" "$APTLY_REPO_NAME"
    else
        aptly -config="$APTLY_CONFIG" publish repo --skip-signing "$APTLY_REPO_NAME"
    fi
    rsync -av "$APTLY_ROOTDIR"/public/* "$REPO_DIR"
    # Remove unnecessary files
    rm -rf "$REPO_DIR/conf/" "$REPO_DIR/db/" "$APTLY_ROOTDIR" "$APTLY_CONFIG"
done

# Ensure we sign the Yum repo meta-data
if [[ "$DISABLE_SIGNING" != "true" ]]; then
    # We use this form to fail on error during the find, otherwise -exec will succeed or just do one file with +
    while IFS= read -r -d '' REPO_METADATA_FILE
    do
        echo "Signing $REPO_METADATA_FILE"
        gpg --detach-sign --batch --armor --yes -u "$GPG_KEY" "$REPO_METADATA_FILE"
    done < <(find "$BASE_PATH" -name repomd.xml -print0)
    # Debug ouput for checking
    find "$BASE_PATH" -name "repomd.xml*" -exec ls -l {} \;
fi
