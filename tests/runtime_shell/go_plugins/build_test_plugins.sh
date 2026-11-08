#!/bin/bash

# Build script for Go test plugins
set -e

GO_PLUGIN_DIR="${FLB_ROOT}/tests/runtime_shell/go_plugins"
BUILD_DIR="${FLB_ROOT}/build"

# Compare the toolchain selected by the plugin module with its minimum Go version.
go_toolchain_compatible() {
    if ! command -v go > /dev/null 2>&1; then
        return 1
    fi

    GO_REQUIRED_VERSION=$(awk '$1 == "go" { print $2; exit }' "$GO_PLUGIN_DIR/go.mod")
    GO_CURRENT_VERSION=$(CDPATH= cd "$GO_PLUGIN_DIR" && GO111MODULE=on go version | awk '{
        for (i = 3; i <= NF; i++) {
            if ($i ~ /^go[0-9]+\.[0-9]+/) {
                sub(/^go/, "", $i)
                sub(/[^0-9.].*$/, "", $i)
                print $i
                exit
            }
        }
    }')
    awk -v current="$GO_CURRENT_VERSION" -v required="$GO_REQUIRED_VERSION" 'BEGIN {
        if (current !~ /^[0-9]+\.[0-9]+(\.[0-9]+)?$/ || required == "") {
            exit 1
        }
        split(current, actual, ".")
        split(required, minimum, ".")
        for (i = 1; i <= 3; i++) {
            if (actual[i] + 0 > minimum[i] + 0) exit 0
            if (actual[i] + 0 < minimum[i] + 0) exit 1
        }
        exit 0
    }'
}

# Reuse a compatible compiler, or install and verify the pinned toolchain.
install_go_if_needed() {
    if ! go_toolchain_compatible; then
    echo "A compatible Go toolchain was not found, installing Go..."

    ARCH=$(uname -m)
    case $ARCH in 
        x86_64) GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    GO_VERSION="1.25.4"
    GO_TARBALL="go${GO_VERSION}.${OS}-${GO_ARCH}.tar.gz"
    GO_URL="https://golang.org/dl/${GO_TARBALL}"

    GO_INSTALL_DIR="${BUILD_DIR}/go-toolchain-${GO_VERSION}"
    if [ -x "$GO_INSTALL_DIR/bin/go" ]; then
        export GOROOT="$GO_INSTALL_DIR"
        export PATH="$GO_INSTALL_DIR/bin:$PATH"
        if go_toolchain_compatible; then
            echo "Reusing the test Go toolchain at $GO_INSTALL_DIR"
            return 0
        fi
    fi

    mkdir -p "$BUILD_DIR"
    TEMP_DIR=$(mktemp -d "${BUILD_DIR}/go-setup.XXXXXX")
    echo "Downloading Go from $GO_URL..."
    if ! command -v curl > /dev/null 2>&1; then
        echo "curl is required to download Go."
        rm -rf "$TEMP_DIR"
        return 1
    fi
    if ! curl -fL --connect-timeout 30 --max-time "${GO_DOWNLOAD_TIMEOUT:-300}" -o "$TEMP_DIR/$GO_TARBALL" "$GO_URL"; then
        rm -rf "$TEMP_DIR"
        return 1
    fi
    if ! tar -xzf "$TEMP_DIR/$GO_TARBALL" -C "$TEMP_DIR"; then
        rm -rf "$TEMP_DIR"
        return 1
    fi

    rm -rf "$GO_INSTALL_DIR"
    mv "$TEMP_DIR/go" "$GO_INSTALL_DIR"
    rm -rf "$TEMP_DIR"
    export GOROOT="$GO_INSTALL_DIR"
    export PATH="$GO_INSTALL_DIR/bin:$PATH"
    echo "Go installed successfully."
    go version
    if ! go_toolchain_compatible; then
        echo "Installed Go does not satisfy the plugin module requirement."
        exit 1
    fi
else
    echo "A compatible Go toolchain is already installed."
fi
}

verify_go_cgo() {
    echo "Verifying Go CGO support..."
    if ! go env CGO_ENABLED | grep -q "1"; then
        echo "Warning: CGO is not enabled. Attempting to enable CGO..."
        export CGO_ENABLED=1
    fi

    TEMP_GO_FILE=$(mktemp --suffix=.go)
    cat > "$TEMP_GO_FILE" << 'EOF'
package main
import "C"
//export TestFunc
func TestFunc() {}
func main() {}
EOF
    TEMP_SO_FILE=$(mktemp --suffix=.so)
    if go build -buildmode=c-shared -o "$TEMP_SO_FILE" "$TEMP_GO_FILE" 2> /dev/null; then
        echo "CGO is enabled and working."
        rm -f "$TEMP_GO_FILE" "$TEMP_SO_FILE"
    else
        echo "Error: CGO is not enabled or not working properly. Please ensure you have a C compiler installed."
        rm -f "$TEMP_GO_FILE" "$TEMP_SO_FILE"
        exit 1
    fi
}

build_go_plugins() {
    echo "Building Go test plugins..."

    echo "Building logs output plugin..."
    cd "$GO_PLUGIN_DIR"
    CGO_ENABLED=1 GO111MODULE=on go build -buildmode=c-shared -v -ldflags="-s -w" -o "$BUILD_DIR/test_logs_go.so" logs_output.go
    if [ $? -eq 0 ]; then 
        echo "Go test plugins built successfully!"
        echo "Logs plugin: $BUILD_DIR/test_logs_go.so"
    else
        echo "Failed to build Go test plugins."
        exit 1
    fi
}

# Hold a checkout-local lock through installation and plugin compilation.
# Kernel locks are released if the test or its compiler is terminated.
mkdir -p "$BUILD_DIR"
(
    if ! command -v flock > /dev/null 2>&1; then
        echo "flock is required to serialize Go plugin builds."
        exit 1
    fi
    GO_SETUP_WAIT=0
    until flock -n 9; do
        GO_SETUP_WAIT=$((GO_SETUP_WAIT + 1))
        if [ "$GO_SETUP_WAIT" -ge "${GO_PLUGIN_LOCK_TIMEOUT:-300}" ]; then
            echo "Timed out waiting for Go plugin setup at $BUILD_DIR"
            exit 1
        fi
        sleep 1
    done
    # Only this lock owner can have an active setup in this build directory.
    rm -rf "$BUILD_DIR"/go-setup.*
    echo "Setting up Go build environment..."
    install_go_if_needed
    verify_go_cgo
    build_go_plugins
) 9>"$BUILD_DIR/go-plugin-build.lock"
