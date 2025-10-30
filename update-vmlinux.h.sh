#!/bin/bash

set -ex

# Clone the vmlinux.h repository with depth=1 into /tmp
REPO_DIR="/tmp/vmlinux.h"
git clone --depth=1 https://github.com/libbpf/vmlinux.h.git "$REPO_DIR"

# Copy the architecture-specific vmlinux.h files
cp "$REPO_DIR/include/aarch64/vmlinux.h" "src/bpf/vmlinux-aarch64.h"
cp "$REPO_DIR/include/x86_64/vmlinux.h" "src/bpf/vmlinux-x86_64.h"

# Clean up - remove the cloned repository
rm -rf "$REPO_DIR"

echo "Successfully updated vmlinux.h files for aarch64 and x86_64"