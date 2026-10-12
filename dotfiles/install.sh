#!/usr/bin/env bash
# Symlinks these configs into ~/.config and installs packages (Arch via pacman/yay).
# Usage: ./install.sh [--packages]
set -euo pipefail

DOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}"

link() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "$dst")"
    if [ -e "$dst" ] && [ ! -L "$dst" ]; then
        mv "$dst" "$dst.bak.$(date +%s)"
        echo "backed up $dst"
    fi
    ln -sfn "$src" "$dst"
    echo "linked $dst -> $src"
}

if [ "${1:-}" = "--packages" ]; then
    if command -v pacman >/dev/null; then
        sudo pacman -S --needed --noconfirm \
            hyprland waybar kitty tmux neovim zsh lsd lazygit git-delta starship \
            rofi-wayland dunst wl-clipboard cliphist swww \
            ttf-jetbrains-mono-nerd zsh-autosuggestions zsh-syntax-highlighting \
            ripgrep fd nodejs npm curl
    elif command -v apt-get >/dev/null; then
        echo "Debian/Ubuntu: Hyprland is not packaged on older releases; install it from https://wiki.hyprland.org/Getting-Started/Installation/"
        sudo apt-get install -y waybar kitty tmux neovim zsh lsd git-delta curl ripgrep fd-find nodejs npm \
            zsh-autosuggestions zsh-syntax-highlighting fonts-jetbrains-mono
        echo "Also install lazygit (https://github.com/jesseduffield/lazygit) and a JetBrainsMono Nerd Font (https://www.nerdfonts.com)."
    else
        echo "Unknown distro: install hyprland waybar kitty tmux neovim zsh lsd lazygit and a Nerd Font manually."
    fi
fi

link "$DOT/hypr"    "$CFG/hypr"
link "$DOT/waybar"  "$CFG/waybar"
link "$DOT/kitty"   "$CFG/kitty"
link "$DOT/tmux"    "$CFG/tmux"
link "$DOT/nvim"    "$CFG/nvim"
link "$DOT/lazygit" "$CFG/lazygit"
link "$DOT/zsh/.zshrc" "$HOME/.zshrc"

echo
echo "Done. Next:"
echo "  1. Put a wallpaper at ~/.config/hypr/wallpaper.jpg"
echo "  2. chsh -s \$(which zsh)"
echo "  3. Log into Hyprland, open kitty (tmux starts automatically), run: nvim   (lazy.nvim installs plugins on first launch)"
echo "  4. In tmux press  C-a P  to build the Editor / Terminal / project+lazygit windows"
