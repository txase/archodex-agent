#!/usr/bin/env -S bash -xe

DEVCONTAINER_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$DEVCONTAINER_DIR/.."

# Don't remove apt cache after installing packages
sudo rm /etc/apt/apt.conf.d/docker-clean

wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
sudo sh -c 'echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-20 main" > /etc/apt/sources.list.d/llvm.list'

sudo apt-get update
sudo apt-get install -y --no-install-recommends clang-20 clang-format-20 libpolly-20-dev libssl-dev libzstd-dev llvm-20-dev lsb-release mold pmake protobuf-compiler

sudo ./register_clang_version.sh 20 100

rustup component add clippy rustfmt

# Build and install elftoolchain with elfutils stubs
pushd "$HOME"
# Check if elftoolchain directory already exists
if [ ! -d elftoolchain/.git ]; then
    git clone --depth=1 https://github.com/Archodex/elftoolchain.git

    cd elftoolchain
    CC=cc pmake SUBDIR=common
    pmake -j$(nproc) SUBDIR=libelf
    pmake SUBDIR=libelf NOMAN=yes install
else
    echo "elftoolchain directory already exists, skipping build"

    cd elftoolchain
    pmake SUBDIR=libelf NOMAN=yes install
fi

git config --global --add safe.directory /root/elftoolchain
popd

# Launch debugger as root
LLDB_SERVER_PATH=""
echo "Waiting for lldb-server to be installed..."
while [ -z "$LLDB_SERVER_PATH" ]; do
    LLDB_SERVER_PATH="$(find ~/.vscode-server/extensions -name lldb-server)"
    if [ -z "$LLDB_SERVER_PATH" ]; then
        sleep 1
    fi
done
echo "Found lldb-server at: $LLDB_SERVER_PATH"
sudo chown root:root "$LLDB_SERVER_PATH"
sudo chmod a+s "$LLDB_SERVER_PATH"

# Install act
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash -s -- -b /usr/bin