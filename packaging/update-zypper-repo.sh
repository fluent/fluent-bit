#!/bin/bash
set -eux

# Used to update a SUSE repository, e.g. during a staging build or release process

# SUSE/openSUSE version and arch, e.g. "opensuse/leap/15.6" or "sles/15-sp5"
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
    rpm --showrc | grep gpg
    rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
fi

# createrepo is available on SUSE
CREATE_REPO_CMD="createrepo"
CREATE_REPO_ARGS=${CREATE_REPO_ARGS:--dvp}

# Check for createrepo
if ! command -v createrepo &> /dev/null; then
    echo "ERROR: 'createrepo' command not found. Please install it, e.g., 'zypper install createrepo'."
    exit 1
fi

echo "INFO: updating $RPM_REPO"

REPO_DIR=$(realpath -sm "$BASE_PATH/$RPM_REPO")
if [[ ! -d "$REPO_DIR" ]]; then
    echo "ERROR: missing $REPO_DIR"
    exit 1
fi

if [[ "$DISABLE_SIGNING" != "true" ]]; then
    # Sign all RPMs created for this target, cover both fluent-bit and legacy packages
    find "$REPO_DIR" -name "*-bit-*.rpm" -exec rpm --define "_gpg_name $GPG_KEY" --addsign {} \;
fi

# Create full metadata for all RPMs in the directory
"$CREATE_REPO_CMD" "$CREATE_REPO_ARGS" "$REPO_DIR"

# Set up repo info in SUSE format
if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
    # Create top-level file and replace path separator with dash
    # opensuse/leap/15.6 --> opensuse-leap-15.6.repo
    REPO_TYPE=${RPM_REPO//\//-}
    echo "INFO: setting up $BASE_PATH/$REPO_TYPE.repo"
    cat << EOF > "$BASE_PATH/$REPO_TYPE.repo"
[Fluent-Bit]
name=Fluent Bit Packages - $REPO_TYPE
type=rpm-md
baseurl=https://$AWS_S3_BUCKET.s3.amazonaws.com/$RPM_REPO/
enabled=1
gpgkey=https://$AWS_S3_BUCKET.s3.amazonaws.com/fluentbit.key
gpgcheck=1
autorefresh=1
EOF
fi

# Ensure we sign the repository metadata
if [[ "$DISABLE_SIGNING" != "true" ]]; then
    while IFS= read -r -d '' REPO_METADATA_FILE; do
        echo "INFO: signing $REPO_METADATA_FILE"
        gpg --detach-sign --batch --armor --yes -u "$GPG_KEY" "$REPO_METADATA_FILE"
    done < <(find "$REPO_DIR" -name repomd.xml -print0)
    # Debug output for checking
    find "$REPO_DIR" -name "repomd.xml*" -exec ls -l {} \;
fi

echo "INFO: Completed $RPM_REPO"
