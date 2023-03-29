#!/bin/sh
set -ex

if [ "$SKIP_TEST" = "yes" ]; then
    echo "Skipping test"
    exit 0
fi

echo "Check package installed"
rpm -q fluent-bit || dpkg -l fluent-bit

echo "Check service enabled"
systemctl is-enabled fluent-bit

until systemctl is-system-running; do
    # On more recent systems we may see degrade when running
    [ "$(systemctl is-system-running)" = "degraded" ] && break
    systemctl --failed
    sleep 10
done

echo "Check service running"
systemctl status -q --no-pager fluent-bit
