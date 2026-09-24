#!/usr/bin/env bash
#
# install.sh — install dependencies for the apk-drill secret-scanning pipeline.
# Target: Ubuntu/Debian x86_64 or arm64. Adjust for other distros.
#
# Installs:
#   - apkeep      (APK downloader; APKPure/Play/F-Droid) — prebuilt binary,
#                 falling back to cargo if no prebuilt matches this arch
#   - trufflehog  (secret scanner with live verification) via official script
#   - unzip, python3, curl  (usually already present)
#
set -euo pipefail

APKEEP_VERSION="${APKEEP_VERSION:-1.0.0}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

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
    # official install script drops the binary in $BIN_DIR
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b "$BIN_DIR"
    echo "    installed: $(trufflehog --version 2>&1 | head -n1)"
fi

# ---- apkeep ----
# Prefer the prebuilt release binary: installing a full Rust toolchain just to
# build a downloader is ~1.5 GB and several minutes of CPU.
apkeep_target() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)          echo "apkeep-x86_64-unknown-linux-gnu" ;;
        Linux-aarch64|Linux-arm64) echo "apkeep-aarch64-unknown-linux-gnu" ;;
        Linux-armv7l)          echo "apkeep-armv7-unknown-linux-gnueabihf" ;;
        *)                     echo "" ;;
    esac
}

if command -v apkeep >/dev/null 2>&1; then
    echo "==> apkeep already installed: $(apkeep --version 2>&1 | head -n1)"
else
    asset="$(apkeep_target)"
    if [ -n "$asset" ]; then
        url="https://github.com/EFForg/apkeep/releases/download/${APKEEP_VERSION}/${asset}"
        echo "==> Installing apkeep ${APKEEP_VERSION} (prebuilt: ${asset})…"
        tmp="$(mktemp)"
        if curl -sSfL "$url" -o "$tmp"; then
            sudo install -m 0755 "$tmp" "${BIN_DIR}/apkeep"
            rm -f "$tmp"
            echo "    installed: $(apkeep --version 2>&1 | head -n1)"
        else
            rm -f "$tmp"
            echo "    prebuilt download failed ($url)."
            asset=""
        fi
    fi

    if ! command -v apkeep >/dev/null 2>&1; then
        echo "==> Falling back to cargo…"
        if command -v cargo >/dev/null 2>&1; then
            cargo install apkeep
        else
            echo "    cargo (Rust) not found and no prebuilt binary for this arch."
            echo "    Option A: install Rust, then re-run:"
            echo "        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            echo "        source \$HOME/.cargo/env && cargo install apkeep"
            echo "    Option B: grab a binary from"
            echo "        https://github.com/EFForg/apkeep/releases"
            echo "        and place it on your PATH."
            exit 1
        fi
    fi
fi

echo ""
echo "==> Done. Verify:"
echo "      apkeep --version"
echo "      trufflehog --version"

# --- optional: androguard for the attack-surface mapper (apk_surface_map.py) ---
echo ""
echo "==> Optional: androguard (manifest analysis for apk_surface_map.py)"
if command -v pip3 >/dev/null 2>&1; then
    pip3 install --quiet androguard 2>/dev/null \
        && echo "    androguard installed" \
        || echo "    androguard install skipped (pip failed) — mapper still runs, minus manifest analysis"
else
    echo "    pip3 not found — skip; the mapper runs without it (minus manifest analysis)"
fi
