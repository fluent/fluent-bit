#!/bin/bash
set -eux
# VERSION must be defined
VERSION=${VERSION:-$1}
# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$2}

RPM_REPO_PATHS=("amazonlinux/2" "centos/7" "centos/8")

echo "RPM signing configuration"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    echo "Updating $RPM_REPO"
    REPO_DIR=$( realpath -sm "$BASE_PATH/$RPM_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue

    # Sign all RPMs created for this version
    find "$REPO_DIR" -name "*-bit-${VERSION}*.rpm" -exec rpm --define "_gpg_name $GPG_KEY" --addsign {} \;

    # Create full metadata for all RPMs in the directory
    createrepo -dvp "$REPO_DIR"

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
EOF
    fi
done

DEB_REPO_PATHS=( "debian/bullseye"
                 "debian/stretch"
                 "debian/buster"
                 "ubuntu/xenial"
                 "ubuntu/bionic"
                 "ubuntu/focal"
                 "raspbian/buster" )

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

    aptly -config="$APTLY_CONFIG" repo add "$APTLY_REPO_NAME" "$REPO_DIR/"
    aptly -config="$APTLY_CONFIG" repo show "$APTLY_REPO_NAME"
    aptly -config="$APTLY_CONFIG" publish repo -gpg-key="$GPG_KEY" "$APTLY_REPO_NAME"
    mv "$APTLY_ROOTDIR"/public/* "$REPO_DIR"/

    # Remove unnecessary files
    rm -rf "$REPO_DIR/conf/" "$REPO_DIR/db/" "$APTLY_ROOTDIR" "$APTLY_CONFIG"
done
