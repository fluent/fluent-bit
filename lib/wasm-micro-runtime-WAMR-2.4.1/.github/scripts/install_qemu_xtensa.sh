#! /bin/sh

set -e

URL=https://github.com/espressif/qemu/releases/download/esp-develop-9.0.0-20240606/qemu-xtensa-softmmu-esp_develop_9.0.0_20240606-x86_64-linux-gnu.tar.xz

DIR=$(mktemp -d)
cd ${DIR}
curl -fLsS "${URL}" | xzcat | tar -x
ln -s ${DIR}/qemu/bin/qemu-system-xtensa /usr/local/bin/qemu-system-xtensa
