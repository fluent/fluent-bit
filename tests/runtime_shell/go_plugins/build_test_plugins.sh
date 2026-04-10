#!/bin/bash

# Build script for Go test plugins
set -e

GO_PLUGIN_DIR="${FLB_ROOT}/tests/runtime_shell/go_plugins"
BUILD_DIR="${FLB_ROOT}/build"

# Support of environment without sudo, but running as root user.
# Like container used in run_code_analysis.sh script.
sudo_if_not_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

install_go_if_needed() {
    if ! command -v go &> /dev/null; then 
    echo "Go not found, installing Go..."

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

    echo "Downloading Go from $GO_URL..."

    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    if command -v curl > /dev/null 2>&1; then
        curl -L -O "$GO_URL"
    else
        echo "Neither wget nor curl is available to download Go."
        exit 1
    fi

    echo "Extracting Go tarball..."
    ls -la

    if [ ! -f "$GO_TARBALL" ]; then
        echo "Failed to download Go tarball."
        exit 1
    fi

    tar -xzf "$GO_TARBALL"

    if [ -w "/usr/local" ]; then
        if [ -d /usr/local/go ]; then
            sudo_if_not_root rm -rf /usr/local/go
        fi
        sudo_if_not_root mv go /usr/local/go
        export PATH="/usr/local/go/bin:$PATH"
    else
        echo "No write permission to /usr/local. Installing Go to $HOME/.local/go"
        mkdir -p "$HOME/.local"
        rm -rf "$HOME/.local/go"
        mv go "$HOME/.local/go"
        export PATH="$HOME/.local/go/bin:$PATH"
    fi
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    echo "Go installed successfully."
    go version 
else
    echo "Go is already installed."
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
    CGO_ENABLED=1 GO111MODULE=on go build -buildmode=c-shared -v -ldflags="-s -w" -o $BUILD_DIR/test_logs_go.so logs_output.go
    if [ $? -eq 0 ]; then 
        echo "Go test plugins built successfully!"
        echo "Logs plugin: $BUILD_DIR/test_logs_go.so"
    else
        echo "Failed to build Go test plugins."
        exit 1
    fi
}

echo "Setting up Go build environment..."
install_go_if_needed
verify_go_cgo
build_go_plugins