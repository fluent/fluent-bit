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

    # Sign our packages
    find "$REPO_DIR" -name "td-agent-bit*.deb" -exec debsigs --sign=origin -k "$GPG_KEY" {} \;

    # Set up directory structure
    mkdir -p "$REPO_DIR/dists/$CODENAME"
    mkdir -p "$REPO_DIR/pool/main/t/td-agent-bit"
    mkdir -p "$REPO_DIR/pool/main/t/td-agent-bit-headers"
    mkdir -p "$REPO_DIR/pool/main/t/td-agent-bit-headers-extra"
    mv "$REPO_DIR"/td-agent-bit*-headers-extra.deb "$REPO_DIR/pool/main/t/td-agent-bit-headers-extra/"
    mv "$REPO_DIR"/td-agent-bit*-headers.deb "$REPO_DIR/pool/main/t/td-agent-bit-headers/"
    mv "$REPO_DIR"/td-agent-bit*.deb "$REPO_DIR/pool/main/t/td-agent-bit/"

    # All paths must be relative and using `dists/CODENAME` for the package info
    pushd "$REPO_DIR"
    apt-ftparchive packages . > "$REPO_DIR/dists/$CODENAME"/Packages
    apt-ftparchive contents . > "$REPO_DIR/dists/$CODENAME"/Contents
    popd
    gzip -c -f "$REPO_DIR/dists/$CODENAME"/Packages > "$REPO_DIR/dists/$CODENAME"/Packages.gz
    gzip -c -f "$REPO_DIR/dists/$CODENAME"/Contents > "$REPO_DIR/dists/$CODENAME"/Contents.gz

    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin="Fluent Bit" \
        -o APT::FTPArchive::Release::Suite="focal" \
        -o APT::FTPArchive::Release::Codename="$CODENAME" \
        -o APT::FTPArchive::Release::Version="$VERSION" \
        -o APT::FTPArchive::Release::Architectures="amd64 arm64 armhf" \
        -o APT::FTPArchive::Release::Components="main" \
        release "$REPO_DIR/dists/$CODENAME" > "$REPO_DIR/dists/$CODENAME"/Release
    gpg --yes --clearsign -o "$REPO_DIR/dists/$CODENAME"/InRelease --local-user "$GPG_KEY" --detach-sign "$REPO_DIR/dists/$CODENAME"/Release
done
