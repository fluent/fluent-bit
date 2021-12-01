#!/bin/bash
set -eu
# VERSION must be defined
VERSION=${VERSION:-$1}
# Where the base of all the repos is
BASE_PATH=${BASE_PATH:-$2}

RPM_REPO_PATHS=("amazonlinux/2/" "centos/7/")

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    echo "Updating $RPM_REPO"
    for ARCH in x86_64 aarch64; do
        REPO_DIR="$BASE_PATH/$RPM_REPO"
        RPM="$REPO_DIR/td-agent-bit-${VERSION}-1.$ARCH.rpm"
        [[ ! -d "$REPO_DIR" ]] && continue
        [[ ! -f "$RPM" ]] && continue

        echo "Updating $RPM_REPO/$ARCH"
        # Sign the RPM
        rpm --addsign "$RPM"
        # Full repo
        # createrepo -dp "$REPO_DIR"
        # Latest version only
        createrepo -n "$RPM" "$REPO_DIR"
    done
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
    REPO_DIR="$BASE_PATH/$DEB_REPO"
    [[ ! -d "$REPO_DIR" ]] && continue

    echo "Updating $DEB_REPO"

    find "$REPO_DIR" -name "td-agent-bit-${VERSION}_*.deb" -exec debsigs --sign=origin -k "$GPG_KEY" {} \;
    dpkg-scanpackages -m "$REPO_DIR" | gzip -c > "$REPO_DIR"/Packages.gz

    # REPO_NAME="flb-${DEB_REPO/\//-}"
    # VERSIONED_REPO_NAME="fluent-bit-${DEB_REPO//\//-}-$VERSION"
    # DISTRBUTION=${DEB_REPO##*/}

    # # Full repo
    # # aptly repo add "$REPO_NAME" "$REPO_DIR/*.deb"

    # # Latest version only
    # aptly repo add "$REPO_NAME" "$REPO_DIR/td-agent-bit_${VERSION}_*.deb"
    # aptly snapshot create "$VERSIONED_REPO_NAME" from repo "$REPO_NAME"
    # aptly publish snapshot -distribution="${DISTRBUTION}" "$VERSIONED_REPO_NAME" \
    #     "filesystem:${DEB_REPO}:"
done