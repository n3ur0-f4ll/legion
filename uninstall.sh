#!/usr/bin/env bash
# Legion — uninstaller
# Removes all Legion files, data and desktop integration from this machine.
# Does NOT remove system packages (python-gobject, webkit2gtk, etc.) —
# they may be used by other applications.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}✓${RESET} $*"; }
info() { echo -e "${CYAN}→${RESET} $*"; }
warn() { echo -e "${YELLOW}⚠${RESET} $*"; }
ask()  { echo -e "${YELLOW}?${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo -e "${BOLD}${RED}Legion — Uninstaller${RESET}"
echo

# ── confirm ───────────────────────────────────────────────────────────────────
warn "This will remove:"
echo "  • Virtual environment (.venv/)"
echo "  • Launcher script (./legion)"
echo "  • Desktop entry (~/.local/share/applications/legion.desktop)"
echo "  • Application icon (~/.local/share/icons/hicolor/256x256/apps/legion.png)"
echo
ask "Remove your personal Legion data (identity, messages, contacts)? [y/N]"
read -r REMOVE_DATA
echo

ask "Are you sure you want to uninstall Legion? [y/N]"
read -r CONFIRM
echo

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

# ── remove personal data ──────────────────────────────────────────────────────
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/legion"
    if [ -d "$DATA_DIR" ]; then
        info "Removing personal data: $DATA_DIR"
        rm -rf "$DATA_DIR"
        ok "Personal data removed"
    else
        info "No personal data directory found — nothing to remove"
    fi
else
    warn "Personal data kept at: ${XDG_DATA_HOME:-$HOME/.local/share}/legion"
    warn "Delete it manually if needed: rm -rf ~/.local/share/legion"
fi

# ── remove virtual environment ────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"
if [ -d "$VENV_DIR" ]; then
    info "Removing virtual environment…"
    rm -rf "$VENV_DIR"
    ok "Virtual environment removed"
fi

# ── remove launcher script ────────────────────────────────────────────────────
LAUNCHER="$SCRIPT_DIR/legion"
if [ -f "$LAUNCHER" ]; then
    rm -f "$LAUNCHER"
    ok "Launcher script removed"
fi

# ── remove desktop integration ────────────────────────────────────────────────
DESKTOP_FILE="$HOME/.local/share/applications/legion.desktop"
if [ -f "$DESKTOP_FILE" ]; then
    rm -f "$DESKTOP_FILE"
    ok "Desktop entry removed"
fi

ICON_FILE="$HOME/.local/share/icons/hicolor/256x256/apps/legion.png"
if [ -f "$ICON_FILE" ]; then
    rm -f "$ICON_FILE"
    # Refresh icon cache (best-effort)
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
    ok "Application icon removed"
fi

# ── note about system packages ────────────────────────────────────────────────
echo
warn "System packages (python-gobject, webkit2gtk, tor, wl-clipboard) were NOT removed."
warn "They may be used by other applications. Remove them manually if needed:"
echo
echo "  Arch:    sudo pacman -Rs python-gobject webkit2gtk-4.1 wl-clipboard"
echo "  Debian:  sudo apt remove python3-gi gir1.2-webkit2-4.1 wl-clipboard"
echo "  Fedora:  sudo dnf remove python3-gobject webkit2gtk4.1 wl-clipboard"
echo

# ── note about repository ─────────────────────────────────────────────────────
warn "The Legion repository directory was NOT removed."
warn "To fully remove Legion from your system:"
echo
echo "  cd .. && rm -rf $(basename "$SCRIPT_DIR")"
echo

echo -e "${BOLD}${GREEN}Legion uninstalled.${RESET}"
echo
