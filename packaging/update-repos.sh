#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Wrapper script around the actual ones used in CI
# Intended only for legacy/manual use in event of failure in CI
# Ensure to add dependencies, e.g. for Ubuntu 22.04: awscli git createrepo-c debsigs aptly rsync gnupg2
# Following that there are a few things to do:
# Import the signing key (if signing)
# gpg --import <private key>
# gpg --export -a "$GPG_KEY" > /tmp/fluentbit.key
# rpm --import /tmp/fluentbit.key

export BASE_PATH=${BASE_PATH:-$1}
if [[ ! -d "$BASE_PATH" ]]; then
    echo "Specified BASE_PATH is not a directory: $BASE_PATH"
    exit 1
fi

export DISABLE_SIGNING=${DISABLE_SIGNING:-false}
export CREATE_REPO_CMD=${CREATE_REPO_CMD:-}
export CREATE_REPO_ARGS=${CREATE_REPO_ARGS:--dvp}
# Must be set for signing
if [[ "$DISABLE_SIGNING" != "false" ]]; then
    export GPG_KEY=${GPG_KEY:?}
fi

# Set these to force a manual S3 sync and update
# AWS_SYNC=true
# AWS_S3_BUCKET_RELEASE=packages.fluentbit.io
# AWS_S3_BUCKET_STAGING=fluentbit-staging
export AWS_REGION=${AWS_REGION:-us-east-1}

RPM_REPO_PATHS=("amazonlinux/2" "amazonlinux/2023" "centos/7" "centos/8" "centos/9" "rockylinux/8" "rockylinux/9" "almalinux/8" "almalinux/9" )

if [[ "${AWS_SYNC:-false}" != "false" ]]; then
    aws s3 sync s3://"${AWS_S3_BUCKET_RELEASE:?}" "${BASE_PATH:?}"
fi

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    export RPM_REPO

    if [[ "${AWS_SYNC:-false}" != "false" ]]; then
        aws s3 sync s3://"${AWS_S3_BUCKET_STAGING:?}/$RPM_REPO" "${BASE_PATH:?}/$RPM_REPO"
    fi

    /bin/bash -eux "$SCRIPT_DIR/update-yum-repo.sh"
done

DEB_REPO_PATHS=( "debian/bookworm"
                 "debian/bullseye"
                 "debian/buster"
                 "ubuntu/jammy"
                 "ubuntu/noble"
                 "raspbian/bookworm"
                )

for DEB_REPO in "${DEB_REPO_PATHS[@]}"; do
    export DEB_REPO
    if [[ "${AWS_SYNC:-false}" != "false" ]]; then
        aws s3 sync s3://"${AWS_S3_BUCKET_STAGING:?}/$DEB_REPO" "${BASE_PATH:?}/$DEB_REPO"
    fi
    /bin/bash -eux "$SCRIPT_DIR/update-apt-repo.sh"
done

# Other OS now
if [[ "${AWS_SYNC:-false}" != "false" ]]; then
    aws s3 sync s3://"${AWS_S3_BUCKET_STAGING:?}/macos" "${BASE_PATH:?}/macos"
    aws s3 sync s3://"${AWS_S3_BUCKET_STAGING:?}/windows" "${BASE_PATH:?}/windows"

    # Final review, do not push until checked manually
    aws s3 sync "${BASE_PATH:?}" s3://"${AWS_S3_BUCKET_RELEASE:?}" --exact-timestamps --dryrun
fi
