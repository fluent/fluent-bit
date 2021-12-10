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
    if [[ -n "${AWS_S3_BUCKET}" ]]; then
        REPO_TYPE=${RPM_REPO%%/*}
        echo "Setting up $BASE_PATH/$REPO_TYPE.repo"
        cat << EOF > "$BASE_PATH/$REPO_TYPE.repo"
[Fluent-Bit]
name=Fluent Bit Packages - $REPO_TYPE - \$basearch
baseurl=https://$AWS_S3_BUCKET.amazonaws.com/$RPM_REPO/\$basearch/
enabled=1
gpgkey=https://$AWS_S3_BUCKET.amazonaws.com/fluentbit.key
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

    echo "Updating $DEB_REPO"

    find "$REPO_DIR" -name "td-agent-bit-${VERSION}_*.deb" -exec debsigs --sign=origin -k "$GPG_KEY" {} \;
    dpkg-scanpackages -m "$REPO_DIR" | gzip -c > "$REPO_DIR"/Packages.gz
done
