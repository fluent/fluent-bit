#!/bin/sh

test_custom_calyptia_fleet_yaml() {
    [ -z "${CALYPTIA_FLEET_TOKEN:-}" ] && startSkipping

    export CALYPTIA_FLEET_TOKEN
    export CALYPTIA_FLEET_FORMAT="off"
    export CALYPTIA_FLEET_DIR="${CALYPTIA_FLEET_DIR:-/tmp/fleet-test}"
    rm -rf "$CALYPTIA_FLEET_DIR"

    # Dry-run to check it is valid
    if ! $FLB_BIN -c "$FLB_RUNTIME_SHELL_CONF/custom_calyptia_fleet.conf" --dry-run; then
        fail 'Dry run failed'
    fi

    $FLB_BIN -c "$FLB_RUNTIME_SHELL_CONF/custom_calyptia_fleet.conf" &
    FLB_PID=$!

    # Allow us to register and retrieve fleet config
    sleep 30

    # Check we have YAML files
    if find "$CALYPTIA_FLEET_DIR" -name '*.yaml' -type f -exec false {} +; then
        fail 'No YAML files found'
    else
        find "$CALYPTIA_FLEET_DIR" -name '*.yaml' -type f -exec cat {} \;
    fi

    # Clean up
    kill -15 $FLB_PID || true
}

test_custom_calyptia_fleet_toml() {
    [ -z "${CALYPTIA_FLEET_TOKEN:-}" ] && startSkipping

    export CALYPTIA_FLEET_TOKEN
    export CALYPTIA_FLEET_FORMAT="on"
    export CALYPTIA_FLEET_DIR="${CALYPTIA_FLEET_DIR:-/tmp/fleet-test}"
    rm -rf "$CALYPTIA_FLEET_DIR"

    # Dry-run to check it is valid
    if ! $FLB_BIN -c "$FLB_RUNTIME_SHELL_CONF/custom_calyptia_fleet.conf" --dry-run; then
        fail 'Dry run failed'
    fi

    $FLB_BIN -c "$FLB_RUNTIME_SHELL_CONF/custom_calyptia_fleet.conf" &
    FLB_PID=$!

    # Allow us to register and retrieve fleet config
    sleep 30

    # Check we have no YAML files
    if find "$CALYPTIA_FLEET_DIR" -name '*.yaml' -type f -exec false {} +; then
        echo 'No YAML files found'
    else
        fail 'YAML files found'
    fi

    # Clean up
    kill -15 $FLB_PID || true
}

# The following command launch the unit test
# shellcheck source=/dev/null
. "$FLB_RUNTIME_SHELL_PATH/runtime_shell.env"
