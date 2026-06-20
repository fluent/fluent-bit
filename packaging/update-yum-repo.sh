#!/bin/bash
set -eux

# Used to update a Yum repo, e.g. during a staging build or release process

#("amazonlinux/2" "amazonlinux/2022" "centos/7" "centos/8" "centos/9")
RPM_REPO=${RPM_REPO:?}

# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$1}
if [[ ! -d "$BASE_PATH" ]]; then
    echo "ERROR: invalid base path: $BASE_PATH"
    exit 1
fi

# Set true to prevent signing
DISABLE_SIGNING=${DISABLE_SIGNING:-false}
if [[ "$DISABLE_SIGNING" != "true" ]]; then
    echo "INFO: RPM signing configuration"
    rpm --showrc|grep gpg
    rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
fi

# Handle Ubuntu 18/22 differences - no support on Ubuntu 20
CREATE_REPO_CMD=${CREATE_REPO_CMD:-}
CREATE_REPO_ARGS=${CREATE_REPO_ARGS:--dvp}

# Assume if set we want to use it
if [[ -n "$CREATE_REPO_CMD" ]]; then
    echo "INFO: using $CREATE_REPO_CMD"
elif command -v createrepo &> /dev/null; then
    echo "INFO: found createrepo"
    CREATE_REPO_CMD="createrepo"
elif command -v createrepo_c &> /dev/null; then
    echo "INFO: found createrepo_c"
    CREATE_REPO_CMD="createrepo_c"
else
    echo "ERROR: unable to find a command equivalent to createrepo"
    exit 1
fi

echo "INFO: updating $RPM_REPO"

REPO_DIR=$( realpath -sm "$BASE_PATH/$RPM_REPO" )
if [[ ! -d "$REPO_DIR" ]] ; then
    echo "ERROR: missing $REPO_DIR"
    exit 1
fi

if [[ "$DISABLE_SIGNING" != "true" ]]; then
    # Sign all RPMs created for this target, cover both fluent-bit and legacy packages
    find "$REPO_DIR" -name "*-bit-*.rpm" -exec rpm --define "_gpg_name $GPG_KEY" --addsign {} \;
fi
# Create full metadata for all RPMs in the directory
"$CREATE_REPO_CMD" "$CREATE_REPO_ARGS" "$REPO_DIR"

# Set up repo info
if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
    # Create top-level file so replace path separator with dash
    # centos/8 --> centos-8.repo
    # This way we make sure not to have a mixed repo or overwrite files for each target.
    REPO_TYPE=${RPM_REPO/\//-}
    echo "INFO: setting up $BASE_PATH/$REPO_TYPE.repo"
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

# Ensure we sign the Yum repo meta-data
if [[ "$DISABLE_SIGNING" != "true" ]]; then
    # We use this form to fail on error during the find, otherwise -exec will succeed or just do one file with +
    while IFS= read -r -d '' REPO_METADATA_FILE
    do
        echo "INFO: signing $REPO_METADATA_FILE"
        gpg --detach-sign --batch --armor --yes -u "$GPG_KEY" "$REPO_METADATA_FILE"
    done < <(find "$REPO_DIR" -name repomd.xml -print0)
    # Debug ouput for checking
    find "$REPO_DIR" -name "repomd.xml*" -exec ls -l {} \;
fi

echo "INFO: Completed $RPM_REPO"
