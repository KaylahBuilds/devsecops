# dotfiles — terminal workstation setup

Reproduces the screenshot setup: a blurred, rounded Hyprland desktop with a
pill-style Waybar, a translucent kitty terminal running tmux with the status bar
on top, Neovim with a file tree / buffer tabs / neon transparent theme / bottom
terminal split, `lsd` for file listings, and lazygit as the git TUI pane.

| Layer in the screenshot | What it is | Config |
|---|---|---|
| Rounded top bar, workspace dots, clock, icon pills | Waybar on Hyprland | `hypr/`, `waybar/` |
| Blurred transparent terminal | kitty, opacity 0.85 + Hyprland blur | `kitty/kitty.conf` |
| `AdvBackend  1 Editor  2 Terminal  3 donut*  …  30°C Guwahati` | tmux status bar (top) + wttr.in script | `tmux/` |
| File tree with `✓` / red modified files | nvim-tree | `nvim/lua/plugins/ui.lua` |
| `app-shell.tsx ✕  EditorPreviewP.. ✕` tabs | bufferline.nvim | same |
| Pink/cyan/green code colours on transparent bg | cyberdream.nvim (`transparent = true`) | same |
| `NTERMINAL │ zsh … donut │ 26/53` | lualine.nvim (`nt` mode = NTERMINAL) | same |
| `ls -la` with icons and `852 B` sizes | lsd (aliased in `.zshrc`) | `zsh/.zshrc` |
| Bottom shell inside the editor | toggleterm.nvim, `Ctrl-\` | same |
| Git panel on the right ("GitArbor") | lazygit in a tmux split | `lazygit/config.yml`, `tmux/scripts/dev-layout.tmux` |

`GitArbor v0.0.2` in the screenshot is not a published tool I could locate; lazygit
gives the same panels (working directory, diff, branches, commits, stashes). If you
have the GitArbor binary, run it in place of `lazygit` in `tmux/scripts/dev-layout.tmux`.

## Install

```bash
cd dotfiles
./install.sh --packages   # Arch: installs everything; Debian: installs what apt has and tells you the rest
./install.sh              # only symlink the configs
```

Then:

1. Drop a wallpaper at `~/.config/hypr/wallpaper.jpg` (swww displays it).
2. `chsh -s $(which zsh)` and log out/in to Hyprland.
3. `Super+Enter` opens kitty, which auto-attaches a tmux session.
4. `nvim` — lazy.nvim installs all plugins on first run; `:Mason` installs language servers.
5. Inside tmux press `Ctrl-a P` to lay out the three windows from the screenshot.

Change the weather city with `export WEATHER_CITY="Your City"` (set in `.zshrc`).

## Key bindings

| Where | Keys | Action |
|---|---|---|
| Hyprland | `Super+Enter` / `Super+D` / `Super+Q` | terminal / launcher / close |
| tmux | `Ctrl-a` then `\|` `-` `c` `h j k l` `P` | split / new window / move / dev layout |
| Neovim | `Space e` | toggle file tree |
| Neovim | `Space ff` / `Space fg` | find files / grep |
| Neovim | `Shift-h` / `Shift-l` / `Space x` | prev / next / close buffer tab |
| Neovim | `Ctrl-\` | toggle bottom terminal, `Esc Esc` to leave insert |
| Neovim | `Space gg` | lazygit popup |
