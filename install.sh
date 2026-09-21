#!/usr/bin/env bash
#
# install.sh — install dependencies for the apk-drill secret-scanning pipeline.
# Target: Ubuntu. Adjust for other distros.
#
# Installs:
#   - apkeep      (APK downloader; APKPure/Play/F-Droid) via cargo
#   - trufflehog  (secret scanner with live verification) via official script
#   - unzip, python3  (usually already present)
#
set -euo pipefail

echo "==> Checking base packages (python3, unzip, curl)…"
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo apt-get install -y python3 unzip curl ca-certificates
fi

# ---- trufflehog ----
if command -v trufflehog >/dev/null 2>&1; then
    echo "==> trufflehog already installed: $(trufflehog --version 2>&1 | head -n1)"
else
    echo "==> Installing trufflehog…"
    # official install script drops the binary in /usr/local/bin
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    echo "    installed: $(trufflehog --version 2>&1 | head -n1)"
fi

# ---- apkeep ----
if command -v apkeep >/dev/null 2>&1; then
    echo "==> apkeep already installed."
else
    echo "==> Installing apkeep…"
    if command -v cargo >/dev/null 2>&1; then
        cargo install apkeep
    else
        echo "    cargo (Rust) not found."
        echo "    Option A: install Rust, then re-run:"
        echo "        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "        source \$HOME/.cargo/env && cargo install apkeep"
        echo "    Option B: grab a prebuilt binary from"
        echo "        https://github.com/EFForg/apkeep/releases"
        echo "        and place it on your PATH."
        exit 1
    fi
fi

echo ""
echo "==> Done. Verify:"
echo "      apkeep --help | head -n1"
echo "      trufflehog --version"
