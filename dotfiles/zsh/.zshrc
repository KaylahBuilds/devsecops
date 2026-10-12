# ── zsh ───────────────────────────────────────────────────────────────────────
export EDITOR=nvim
export VISUAL=nvim
export WEATHER_CITY="Guwahati"

HISTFILE=~/.zsh_history
HISTSIZE=50000
SAVEHIST=50000
setopt share_history hist_ignore_dups hist_ignore_space autocd

autoload -Uz compinit && compinit
zstyle ':completion:*' menu select

# Plugins (install via your distro or git clone into ~/.zsh)
[ -f /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh ] && \
    source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
[ -f /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && \
    source /usr/share/zsh/plugins/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

# lsd gives the ".rwxr-xr-x user user 852 B Thu Aug 27 14:42:58 2026 .env" listing
if command -v lsd >/dev/null; then
    alias ls='lsd'
    alias ll='lsd -l'
    alias la='lsd -la'
    alias lt='lsd --tree'
fi
alias v='nvim'
alias g='git'
alias lg='lazygit'
alias t='tmux new-session -A -s main'

# Prompt (starship if present, minimal fallback otherwise)
if command -v starship >/dev/null; then
    eval "$(starship init zsh)"
else
    PROMPT='%F{cyan}%~%f %F{magenta}❯%f '
fi
