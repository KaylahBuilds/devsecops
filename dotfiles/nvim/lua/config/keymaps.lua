local map = vim.keymap.set

map("n", "<leader>e", "<cmd>NvimTreeToggle<cr>",       { desc = "File tree" })
map("n", "<leader>ff", "<cmd>Telescope find_files<cr>", { desc = "Find files" })
map("n", "<leader>fg", "<cmd>Telescope live_grep<cr>",  { desc = "Grep" })
map("n", "<leader>fb", "<cmd>Telescope buffers<cr>",    { desc = "Buffers" })

-- Buffer tabs (bufferline)
map("n", "<S-l>", "<cmd>BufferLineCycleNext<cr>", { desc = "Next buffer" })
map("n", "<S-h>", "<cmd>BufferLineCyclePrev<cr>", { desc = "Prev buffer" })
map("n", "<leader>x", "<cmd>bdelete<cr>",         { desc = "Close buffer" })

-- Bottom terminal split (toggleterm)
map({ "n", "t" }, "<C-\\>", "<cmd>ToggleTerm<cr>", { desc = "Toggle terminal" })
map("t", "<Esc><Esc>", [[<C-\><C-n>]],             { desc = "Terminal → normal mode" })

-- Window navigation
map("n", "<C-h>", "<C-w>h")
map("n", "<C-j>", "<C-w>j")
map("n", "<C-k>", "<C-w>k")
map("n", "<C-l>", "<C-w>l")

map("n", "<leader>gg", "<cmd>LazyGit<cr>", { desc = "LazyGit" })
map("n", "<Esc>", "<cmd>nohlsearch<cr>")
