#!/bin/bash

# Distro and codename
DISTRO=${DISTRO:?}
CODENAME=${CODENAME:?}

# Package version to add
VERSION=${VERSION:?}
# Packages location
SOURCE_DIR=${SOURCE_DIR:-$HOME/apt}
# Aptly config file
APTLY_CONFIG=${APTLY_CONFIG:-/etc/aptly.conf}

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Missing source directory: $SOURCE_DIR"
    exit 1
fi

REPO_NAME="flb-${DISTRO}-${CODENAME}"

if aptly -config="$APTLY_CONFIG" repo show "$REPO_NAME" 2>/dev/null; then 
    echo "Existing repo found for $REPO_NAME"
    exit 1
fi

mkdir -p "/var/www/apt.fluentbit.io/${DISTRO}/${CODENAME}/"

if ! grep -q "debian/bookworm" "$APTLY_CONFIG"; then
    echo "Please update the aptly config file with the following:"
    echo
    echo '   "FileSystemPublishEndpoints": {'
    echo "+    \"${DISTRO}/${CODENAME}\": {"
    echo "+      \"rootDir\": \"/var/www/apt.fluentbit.io/${DISTRO}/${CODENAME}\","
    echo '+      "linkMethod": "copy",'
    echo '+      "verifyMethod": "md5"'
    echo '+    },'
    exit 1
fi

echo "First time publishing ${DISTRO} ${CODENAME}"

# Create repo and add packages
aptly -config=/etc/aptly.conf repo create -distribution="$CODENAME" -component=main "$REPO_NAME"
find "$SOURCE_DIR/${DISTRO}/${CODENAME}/" -iname "*-bit_$VERSION*.deb" -exec aptly -config="$APTLY_CONFIG" repo add "$REPO_NAME" {} \;

# Snapshot and publish
SNAPSHOT_NAME="fluent-bit-${DISTRO}-${CODENAME}-${VERSION}"
aptly -config="$APTLY_CONFIG" snapshot create "$SNAPSHOT_NAME" from repo "$REPO_NAME"
aptly -config="$APTLY_CONFIG" publish snapshot -gpg-key=releases@fluentbit.io "$SNAPSHOT_NAME" "filesystem:${DISTRO}/${COMPONENT}:"
