#!/bin/bash

set -e

ON_S390X="$1"

if [[ "$ON_S390X" != "--on-s390x" ]]; then
    if [ -z "$S390X_USER" ]; then
        echo "S390X_USER not defined";
        exit 1;
    fi
    if [ -z "$LOCAL_KEY" ]; then
        echo "LOCAL_KEY not defined";
        exit 1;
    fi

    SSH_KEY_PATH="v1/devel/kv/cp-env/s390x-key/IBM-Cloud-S390x-key"
    SSH_PRIVATE_KEY_FIELD="private_key"
    SSH_IP_FIELD="ip"
    SSH_KNOWN_HOST="known_host"
    S390X_HOST=$(vault kv get -field=$SSH_IP_FIELD $SSH_KEY_PATH)
    SSH_USER_AT_HOST="$S390X_USER@$S390X_HOST"
    SSH_COMMAND="ssh -o ServerAliveInterval=60 -i ./$LOCAL_KEY $SSH_USER_AT_HOST"
    SCP_COMMAND="scp -i ./$LOCAL_KEY"

    vault kv get -field=$SSH_PRIVATE_KEY_FIELD $SSH_KEY_PATH > ./$LOCAL_KEY
    chmod go-rwx ./$LOCAL_KEY
    echo "SSH Key saved to $LOCAL_KEY"

    if [ -z "$(ssh-keygen -F $S390X_HOST)" ]; then
        S390X_KNOWN_HOST=$(vault kv get -field=$SSH_KNOWN_HOST $SSH_KEY_PATH)
        echo "$S390X_KNOWN_HOST" >> ~/.ssh/known_hosts;
        echo "Added $S390X_HOST to the list of known hosts"
    fi

    DIR=$(mktemp -d --suffix=librdkafka)
    eval $SSH_COMMAND mkdir $DIR
    eval $SCP_COMMAND ./packaging/tools/build-release-artifacts-s390x.sh $SSH_USER_AT_HOST:$DIR/build-release-artifacts-s390x.sh
    echo "Running build on s390x"
    CURRENT_TARGET=$(git symbolic-ref --short -q HEAD || git describe --tags --exact-match 2>/dev/null)
    eval $SSH_COMMAND $DIR/build-release-artifacts-s390x.sh --on-s390x $CURRENT_TARGET "$@"
    RET=$?

    if [ "x$RET" = "x0" ]; then
        DEST_FILE=${@: -1}
        mkdir -p $(dirname $DEST_FILE)
        eval $SCP_COMMAND $SSH_USER_AT_HOST:$DIR/librdkafka/artifacts/librdkafka.tgz $DEST_FILE
        RET=$?
        echo "Copied artifact to Semaphore"
    fi
    if [[ "$DIR" =~ ^/tmp/.*$ ]]; then
        eval $SSH_COMMAND rm -rf $DIR
        RET=$?
        if [ "$RET" != "0" ]; then
            echo "Failed to remove build directory";
        else
            echo "Removed build directory";
        fi
    fi
    exit $RET
fi

export DEBIAN_FRONTEND=noninteractive
CURRENT_TARGET=$2
DIR=$(dirname $0)
shift 2
# Clean up stopped builds
find /tmp -maxdepth 1 -name "tmp.*librdkafka" -mtime +1 -exec rm -rf {} +
echo "ON S390x: Installing pre-requisites"
sudo apt update
sudo apt install -y git ca-certificates curl gnupg

if ! command -v docker >/dev/null 2>&1; then
    echo "Installing docker..."
    # Add Docker's official GPG key:
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources:
    sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl start docker || true
    sudo usermod -aG docker $USER
    echo "User added to docker group"
fi
echo "ON S390x: Cloning librdkafka at branch $CURRENT_TARGET to $DIR/librdkafka"
git clone --depth 1 --single-branch --branch $CURRENT_TARGET https://github.com/confluentinc/librdkafka.git $DIR/librdkafka
cd $DIR/librdkafka
export DEST_FILE=${@: -1}
export DEST_DIR=$(dirname $DEST_FILE)
mkdir -p $DEST_DIR
echo "ON S390x: Running ./packaging/tools/build-release-artifacts.sh $@"
newgrp docker <<EOF
./packaging/tools/build-release-artifacts.sh $@
EOF

