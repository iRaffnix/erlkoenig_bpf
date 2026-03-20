package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/erlkoenig/erlkoenig_bpf_tui/internal/api"
	"github.com/erlkoenig/erlkoenig_bpf_tui/internal/ui"
)

var (
	addr    string
	file    string
	example string
	dslDir  string
	lang    string
)

var rootCmd = &cobra.Command{
	Use:   "ebpf_explorer",
	Short: "Erlkoenig BPF Compiler Explorer TUI",
	Long:  "Interactive TUI for compiling, inspecting, and debugging eBPF programs.\nSupports both EBL and Elixir DSL. Press L to switch language.",
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVar(&addr, "addr", "localhost:8080", "Debugger backend address")
	rootCmd.Flags().StringVar(&file, "file", "", "Load source file (.ebl or .ex)")
	rootCmd.Flags().StringVar(&example, "example", "", "Load built-in example by name")
	rootCmd.Flags().StringVar(&dslDir, "dsl-dir", "", "Directory with Elixir DSL examples (.ex files)")
	rootCmd.Flags().StringVar(&lang, "lang", "", "Source language: ebl or elixir (auto-detected from file extension)")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	baseURL := "http://" + addr
	client := api.NewClient(baseURL)

	// Auto-detect DSL dir if not set
	if dslDir == "" {
		// Try relative to the erlkoenig_bpf project
		candidates := []string{
			filepath.Join(filepath.Dir(os.Args[0]), "..", "dsl", "examples"),
			"/home/erlkoenig/code/erlkoenig_bpf/dsl/examples",
		}
		for _, c := range candidates {
			if fi, err := os.Stat(c); err == nil && fi.IsDir() {
				dslDir = c
				break
			}
		}
	}

	// Determine language
	language := ui.LangEBL
	switch strings.ToLower(lang) {
	case "elixir", "ex", "dsl":
		language = ui.LangElixir
	case "ebl", "":
		// Auto-detect from file extension
		if file != "" && (strings.HasSuffix(file, ".ex") || strings.HasSuffix(file, ".exs")) {
			language = ui.LangElixir
		}
	}

	var source string

	// Load initial source
	if file != "" {
		src, err := ui.LoadFile(file)
		if err != nil {
			return fmt.Errorf("cannot load file %s: %w", file, err)
		}
		source = src
	} else if example != "" {
		src, err := client.LoadExample(example)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot load example %q: %v\n", example, err)
		} else {
			source = src
		}
	}

	model := ui.NewModel(client, source, language, dslDir)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}
