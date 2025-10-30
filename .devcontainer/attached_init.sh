#!/usr/bin/env -S bash -xe

DEVCONTAINER_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /' | tee /etc/apt/sources.list.d/kubernetes.list

apt-get update
apt-get install -y jq kubectl sudo

rustup component add clippy rustfmt

# This must be installed before the init.sh script is run
code --install-extension vadimcn.vscode-lldb

"$DEVCONTAINER_DIR/init.sh"

code --install-extension esbenp.prettier-vscode
code --install-extension github.vscode-github-actions
code --install-extension ms-vscode.cpptools
code --install-extension pbkit.vscode-pbkit
code --install-extension rust-lang.rust-analyzer
code --install-extension tamasfe.even-better-toml
code --install-extension xaver.clang-format