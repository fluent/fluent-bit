#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Wrapper script around the actual ones used in CI

export BASE_PATH=${BASE_PATH:-$1}
export DISABLE_SIGNING=${DISABLE_SIGNING:-false}
export CREATE_REPO_CMD=${CREATE_REPO_CMD:-}
export CREATE_REPO_ARGS=${CREATE_REPO_ARGS:--dvp}

RPM_REPO_PATHS=("amazonlinux/2" "amazonlinux/2022" "centos/7" "centos/8" "centos/9")

for RPM_REPO in "${RPM_REPO_PATHS[@]}"; do
    export RPM_REPO
    /bin/bash "$SCRIPT_DIR/update-yum-repo.sh" &
done

DEB_REPO_PATHS=( "debian/bookworm"
                 "debian/bullseye"
                 "debian/buster"
                 "ubuntu/xenial"
                 "ubuntu/bionic"
                 "ubuntu/focal"
                 "ubuntu/jammy"
                 "raspbian/buster"
                 "raspbian/bullseye" )

for DEB_REPO in "${DEB_REPO_PATHS[@]}"; do
    export DEB_REPO
    /bin/bash "$SCRIPT_DIR/update-apt-repo.sh" &
done

wait
