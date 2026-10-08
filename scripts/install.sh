#!/bin/sh
# Install KubesTUI on macOS or Linux (current user, no root needed).
#
#   curl -fsSL https://raw.githubusercontent.com/usbee100k/KubesTUI/main/scripts/install.sh | sh
#
# A homelabCD bootstrap node serves this same script on your LAN
# ("Share KubesTUI with a Workstation"), with the download address below
# pointing at the node instead of GitHub.

set -eu

base="${KUBESTUI_BASE:-https://github.com/usbee100k/KubesTUI/releases/latest/download}"
dir="${KUBESTUI_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
    linux | darwin) ;;
    *) echo "Unsupported OS: $os" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "Unsupported CPU: $arch" >&2; exit 1 ;;
esac

name="kubestui-$os-$arch"
tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.sums"' EXIT

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    else
        wget -qO "$2" "$1"
    fi
}

echo "Downloading $name from $base ..."
fetch "$base/$name" "$tmp"
fetch "$base/SHA256SUMS" "$tmp.sums"

# Verify the checksum before installing.
want=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); if (f == n) print $1 }' "$tmp.sums")
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp" | awk '{print $1}')
else
    got=$(shasum -a 256 "$tmp" | awk '{print $1}')
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "Checksum mismatch for $name (expected ${want:-none}, got $got). Nothing was installed." >&2
    exit 1
fi

mkdir -p "$dir"
install -m 755 "$tmp" "$dir/kubestui"
echo "Checksum OK. Installed $dir/kubestui"

case ":$PATH:" in
    *":$dir:"*) ;;
    *)
        echo
        echo "$dir is not on your PATH. Add this to your shell profile:"
        echo "  export PATH=\"$dir:\$PATH\""
        ;;
esac

echo
echo "Done. Run:  kubestui"
echo "Then choose 'Connect a new cluster' and enter a control plane's IP."
