#!/bin/sh
set -eux

echo "Check package installed"
rpm -q td-agent-bit || dpkg -l td-agent-bit

echo "Check service enabled"
systemctl is-enabled td-agent-bit

until systemctl is-system-running; do
    sleep 10
done

echo "Check service running"
systemctl status -q --no-pager td-agent-bit
