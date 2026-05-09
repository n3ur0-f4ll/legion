#!/usr/bin/env bash
# Legion — installer
# Supports: Arch/EndeavourOS/Manjaro · Debian/Ubuntu/Mint · Fedora/RHEL/Rocky
# Usage: bash install.sh

set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
die()  { echo -e "${RED}✗${RESET} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── header ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}${CYAN}Legion — Installer${RESET}"
echo -e "Decentralized. Anonymous. Yours."
echo

# ── detect distro family ─────────────────────────────────────────────────────
detect_family() {
    if command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v dnf &>/dev/null; then
        echo "rhel"
    elif command -v yum &>/dev/null; then
        echo "rhel_yum"
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_family)
case "$FAMILY" in
    arch)       info "Detected: Arch / EndeavourOS / Manjaro" ;;
    debian)     info "Detected: Debian / Ubuntu / Mint" ;;
    rhel)       info "Detected: Fedora / RHEL / Rocky / AlmaLinux" ;;
    rhel_yum)   info "Detected: RHEL / CentOS (yum)" ;;
    *)          die "Unsupported distribution. Supported: Arch, Debian/Ubuntu, Fedora/RHEL." ;;
esac

# ── check Python version ──────────────────────────────────────────────────────
info "Checking Python version…"
if ! command -v python3 &>/dev/null; then
    die "python3 not found. Install Python 3.12 or newer first."
fi

PYVER_FULL=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYVER_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYVER_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [ "$PYVER_MAJOR" -lt 3 ] || { [ "$PYVER_MAJOR" -eq 3 ] && [ "$PYVER_MINOR" -lt 12 ]; }; then
    die "Python $PYVER_FULL found, but Legion requires Python 3.12 or newer."
fi
ok "Python $PYVER_FULL"

# ── install system packages ───────────────────────────────────────────────────
info "Installing system packages (requires sudo)…"

case "$FAMILY" in
    arch)
        sudo pacman -S --needed --noconfirm \
            python-gobject \
            webkit2gtk-4.1 \
            wl-clipboard \
            tor
        ;;
    debian)
        sudo apt-get update -qq
        sudo apt-get install -y \
            python3-gi \
            python3-gi-cairo \
            gir1.2-gtk-3.0 \
            gir1.2-webkit2-4.1 \
            wl-clipboard \
            tor \
            python3-venv \
            python3-dev
        ;;
    rhel)
        sudo dnf install -y \
            python3-gobject \
            webkit2gtk4.1 \
            wl-clipboard \
            tor
        ;;
    rhel_yum)
        sudo yum install -y \
            python3-gobject \
            webkit2gtk4 \
            wl-clipboard \
            tor
        ;;
esac
ok "System packages installed"

# ── create virtual environment ────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
info "Creating virtual environment at $VENV_DIR…"
python3 -m venv "$VENV_DIR"
ok "Virtual environment created"

# ── install Python dependencies ───────────────────────────────────────────────
info "Installing Python dependencies…"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet --no-cache-dir
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet --no-cache-dir
ok "Python dependencies installed"

# ── symlink gi into venv ──────────────────────────────────────────────────────
info "Linking system gi (PyGObject) into venv…"

# gi can live in site-packages (Arch, Fedora) or dist-packages (Debian/Ubuntu)
GI_SRC=""
for candidate in \
    "/usr/lib/python3/dist-packages/gi" \
    "/usr/lib/python${PYVER_FULL}/site-packages/gi" \
    "/usr/lib/python${PYVER_MAJOR}/site-packages/gi"; do
    if [ -d "$candidate" ]; then
        GI_SRC="$candidate"
        break
    fi
done

if [ -z "$GI_SRC" ]; then
    # Fallback: search common paths
    GI_SRC=$(find /usr/lib -maxdepth 4 -type d -name "gi" 2>/dev/null | head -1)
fi

if [ -z "$GI_SRC" ]; then
    die "Could not find system gi (PyGObject). Make sure python3-gobject / python-gobject is installed."
fi

GI_DEST="$VENV_DIR/lib/python${PYVER_FULL}/site-packages/gi"

# Remove existing gi (directory or symlink) so ln -sf replaces it, not creates inside it
if [ -e "$GI_DEST" ] || [ -L "$GI_DEST" ]; then
    rm -rf "$GI_DEST"
fi

ln -sf "$GI_SRC" "$GI_DEST"
ok "gi linked: $GI_SRC → $GI_DEST"

# ── verify gi import ──────────────────────────────────────────────────────────
if ! "$VENV_DIR/bin/python" -c "import gi" 2>/dev/null; then
    warn "gi import failed in venv. You may need to link additional GObject libraries."
    warn "Check: $GI_SRC exists and is a valid gi installation."
else
    ok "gi import verified"
fi

# ── create launcher script ────────────────────────────────────────────────────
LAUNCHER="$SCRIPT_DIR/legion"
cat > "$LAUNCHER" << 'EOF'
#!/usr/bin/env bash
LEGION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$LEGION_DIR/.venv/bin/python" "$LEGION_DIR/legion-gui/app/main.py" "$@"
EOF
chmod +x "$LAUNCHER"
ok "Launcher created: $LAUNCHER"

# ── done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}${GREEN}Installation complete.${RESET}"
echo
echo -e "Run Legion with:"
echo -e "  ${BOLD}./legion${RESET}   or   ${BOLD}bash legion${RESET}"
echo
echo -e "To uninstall: ${BOLD}bash uninstall.sh${RESET}"
echo
