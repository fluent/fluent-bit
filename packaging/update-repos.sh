#!/bin/bash
set -eux
# VERSION must be defined
VERSION=${VERSION:-$1}
# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$2}

RPM_REPO_PATHS=("amazonlinux/2" "centos/7")

echo "RPM signing configuration"
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    echo "Updating $RPM_REPO"
    REPO_DIR=$( realpath -sm "$BASE_PATH/$RPM_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue

    # Sign all RPMs created for this version
    find "$REPO_DIR" -name "td-agent-bit-${VERSION}*.rpm" -exec rpm --define "_gpg_name $GPG_KEY" --addsign {} \;

    # Create full metadata for all RPMs in the directory
    createrepo -dvp "$REPO_DIR"

    # Set up repo info
    if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
        REPO_TYPE=${RPM_REPO%%/*}
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

DEB_REPO_PATHS=( "debian/jessie"
                 "debian/stretch"
                 "debian/buster"
                 "ubuntu/xenial"
                 "ubuntu/bionic"
                 "ubuntu/focal"
                 "raspbian/jessie"
                 "raspbian/stretch"
                 "raspbian/buster" )

for DEB_REPO in "${DEB_REPO_PATHS[@]}"; do
    REPO_DIR=$(realpath -sm "$BASE_PATH/$DEB_REPO" )
    [[ ! -d "$REPO_DIR" ]] && continue

    CODENAME=${DEB_REPO##*/}
    echo "Updating $DEB_REPO for $CODENAME"

    # Use reprepro to create the repository, this will sign and create all the metadata very easily
    mkdir -p "$REPO_DIR/conf"
    cat << EOF > "$REPO_DIR/conf/distributions"
Origin: Fluent Bit
Label: Fluent Bit
Codename: $CODENAME
Architectures: amd64 arm64 armhf
Components: main
Description: Apt repository for Fluent Bit
SignWith: $GPG_KEY
EOF
    cat << EOF > "$REPO_DIR/conf/options"
    verbose
    basedir $REPO_DIR
EOF
    pushd "$REPO_DIR" || exit 1
    find "$REPO_DIR" -name "td-agent-bit*.deb" -exec reprepro includedeb "$CODENAME" {} \;
    popd || true

    # Remove unnecessary files
    rm -rf "$REPO_DIR/conf/" "$REPO_DIR/db/"
done
