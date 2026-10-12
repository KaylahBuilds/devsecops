-- Colorscheme, file tree, buffer tabs, statusline, terminal split
return {
  -- Neon dark theme with transparent bg so the wallpaper shows through kitty
  {
    "scottmckendry/cyberdream.nvim",
    lazy = false,
    priority = 1000,
    opts = {
      transparent = true,
      italic_comments = true,
      hide_fillchars = true,
      borderless_pickers = true,
      terminal_colors = true,
    },
    config = function(_, opts)
      require("cyberdream").setup(opts)
      vim.cmd.colorscheme("cyberdream")
    end,
  },

  { "nvim-tree/nvim-web-devicons", lazy = true },

  -- Left file tree with git glyphs (✓ staged, red = modified) like the screenshot
  {
    "nvim-tree/nvim-tree.lua",
    cmd = { "NvimTreeToggle", "NvimTreeFocus" },
    opts = {
      view = { width = 34, side = "left" },
      renderer = {
        root_folder_label = false,
        indent_markers = { enable = true },
        icons = {
          git_placement = "before",
          glyphs = {
            folder = { arrow_closed = "", arrow_open = "" },
            git = {
              unstaged = "✗", staged = "✓", unmerged = "",
              renamed = "➜", untracked = "★", deleted = "", ignored = "◌",
            },
          },
        },
      },
      git = { enable = true, ignore = false },
      filters = { dotfiles = false },
      update_focused_file = { enable = true },
    },
  },

  -- Buffer tabs along the top of the editor
  {
    "akinsho/bufferline.nvim",
    event = "VeryLazy",
    opts = {
      options = {
        mode = "buffers",
        separator_style = "thin",
        show_buffer_close_icons = true,
        show_close_icon = true,
        close_icon = "",
        buffer_close_icon = "",
        modified_icon = "●",
        diagnostics = "nvim_lsp",
        always_show_bufferline = true,
        offsets = { { filetype = "NvimTree", text = "", padding = 0 } },
      },
      highlights = {
        fill = { bg = "NONE" },
        background = { bg = "NONE" },
        buffer_selected = { bg = "NONE", bold = true, italic = false },
      },
    },
  },

  -- Statusline: "NTERMINAL | zsh ........ donut | 26/53"
  {
    "nvim-lualine/lualine.nvim",
    event = "VeryLazy",
    opts = function()
      local colors = {
        bg = "NONE", fg = "#ffffff",
        yellow = "#f1ff5e", pink = "#ff5ea0", cyan = "#5ef1ff",
        green = "#5eff6c", purple = "#bd5eff", dark = "#0d0f12",
      }
      local theme = {
        normal   = { a = { bg = colors.yellow, fg = colors.dark, gui = "bold" }, b = { bg = colors.pink, fg = colors.dark }, c = { bg = colors.bg, fg = colors.fg } },
        insert   = { a = { bg = colors.green,  fg = colors.dark, gui = "bold" } },
        visual   = { a = { bg = colors.purple, fg = colors.dark, gui = "bold" } },
        replace  = { a = { bg = colors.pink,   fg = colors.dark, gui = "bold" } },
        command  = { a = { bg = colors.cyan,   fg = colors.dark, gui = "bold" } },
        terminal = { a = { bg = colors.yellow, fg = colors.dark, gui = "bold" } },
        inactive = { a = { bg = colors.bg, fg = colors.fg }, b = { bg = colors.bg, fg = colors.fg }, c = { bg = colors.bg, fg = colors.fg } },
      }
      local function project()
        return " " .. vim.fn.fnamemodify(vim.fn.getcwd(), ":t")
      end
      local function progress()
        return " " .. vim.fn.line(".") .. "/" .. vim.fn.line("$")
      end
      return {
        options = {
          theme = theme,
          globalstatus = true,
          component_separators = "",
          section_separators = "",
          disabled_filetypes = { statusline = { "NvimTree" } },
        },
        sections = {
          lualine_a = { "mode" },               -- shows NTERMINAL in a terminal buffer
          lualine_b = { { "filename", path = 0, symbols = { modified = " ●", readonly = " " } } },
          lualine_c = { "diagnostics" },
          lualine_x = { "branch", "diff" },
          lualine_y = { { project, color = { fg = colors.dark, bg = colors.yellow } } },
          lualine_z = { { progress, color = { fg = colors.dark, bg = colors.yellow, gui = "bold" } } },
        },
      }
    end,
  },

  -- Bottom terminal split running your shell
  {
    "akinsho/toggleterm.nvim",
    cmd = "ToggleTerm",
    opts = {
      direction = "horizontal",
      size = 12,
      shade_terminals = false,
      start_in_insert = true,
      persist_size = true,
    },
  },

  -- Gutter git signs
  {
    "lewis6991/gitsigns.nvim",
    event = { "BufReadPre", "BufNewFile" },
    opts = {
      signs = {
        add = { text = "▎" }, change = { text = "▎" }, delete = { text = "" },
        topdelete = { text = "" }, changedelete = { text = "▎" },
      },
    },
  },

  { "kdheepak/lazygit.nvim", cmd = "LazyGit", dependencies = { "nvim-lua/plenary.nvim" } },
  { "lukas-reineke/indent-blankline.nvim", main = "ibl", event = "BufReadPost", opts = { scope = { enabled = false } } },
}
