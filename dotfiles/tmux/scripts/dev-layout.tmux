# Recreates the screenshot layout inside the current session.
rename-window -t 1 Editor
send-keys -t 1 "nvim" C-m
new-window -n Terminal
new-window -n "#{b:pane_current_path}"
split-window -h -l 36% -c "#{pane_current_path}"
send-keys "lazygit" C-m
select-pane -L
send-keys "nvim" C-m
