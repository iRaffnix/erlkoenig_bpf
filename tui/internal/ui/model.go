package ui

import (
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/erlkoenig/erlkoenig_bpf_tui/internal/api"
)

const defaultPacket = "ffffffffffff0000000000000800450000280001000040060000c0a80001c0a800020050005000000001000000005002200000000000"

type panel int

const (
	panelSource panel = iota
	panelDisasm
	panelRegisters
)

// Language selects the source language for compilation.
type Language int

const (
	LangEBL    Language = iota // EBL (.ebl files)
	LangElixir                 // Elixir DSL (.ex files)
)

func (l Language) String() string {
	if l == LangElixir {
		return "elixir"
	}
	return "ebl"
}

func (l Language) Label() string {
	if l == LangElixir {
		return "ELIXIR DSL"
	}
	return "EBL"
}

// Model is the bubbletea model for the Compiler Explorer TUI.
type Model struct {
	client *api.Client

	// Compilation / debug state
	source       string
	sourceLines  []string
	language     Language
	instructions []api.Instruction
	ir           string
	state        *api.VMState
	prevRegs     []api.Register // previous register values for change highlighting
	sessionID    string
	sourceMap    map[int][2]int // PC -> [line, col]
	mapSpecs     []api.MapSpec
	compiled     bool
	err          string
	statusMsg    string

	// UI state
	focus        panel
	sourceScroll int
	disasmScroll int
	regScroll    int
	width        int
	height       int
	showHelp     bool

	// Editing
	editing   bool
	cursorLine int
	cursorCol  int

	// Examples
	eblExamples    []string // EBL examples from backend
	elixirExamples []string // Elixir DSL examples from local disk
	examplesErr    string

	// Backend connectivity
	connected bool

	// DSL examples directory
	dslDir string
}

// --- Messages ---

type errMsg struct{ err error }
type statusMsg struct{ msg string }
type initResultMsg struct{ result *api.InitResult }
type stepResultMsg struct{ state *api.VMState }
type runResultMsg struct{ state *api.VMState }
type resetResultMsg struct{ state *api.VMState }
type examplesMsg struct {
	eblExamples    []string
	elixirExamples []string
}
type exampleLoadedMsg struct{ source string }

func (e errMsg) Error() string { return e.err.Error() }

// NewModel creates a new TUI model.
func NewModel(client *api.Client, initialSource string, lang Language, dslDir string) Model {
	m := Model{
		client:   client,
		source:   initialSource,
		language: lang,
		focus:    panelSource,
		dslDir:   dslDir,
	}
	m.sourceLines = strings.Split(m.source, "\n")
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		checkConnectionCmd(m.client),
		loadExamplesCmd(m.client, m.dslDir),
	)
}

func checkConnectionCmd(client *api.Client) tea.Cmd {
	return func() tea.Msg {
		err := client.Ping()
		if err != nil {
			return errMsg{err: err}
		}
		return statusMsg{msg: "Connected to debugger backend"}
	}
}

func loadExamplesCmd(client *api.Client, dslDir string) tea.Cmd {
	return func() tea.Msg {
		eblExamples, _ := client.Examples()
		elixirExamples := scanDSLExamples(dslDir)
		return examplesMsg{eblExamples: eblExamples, elixirExamples: elixirExamples}
	}
}

// scanDSLExamples finds .ex files in the DSL examples directory.
func scanDSLExamples(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && len(e.Name()) > 3 && e.Name()[len(e.Name())-3:] == ".ex" {
			names = append(names, e.Name())
		}
	}
	return names
}

func compileAndInitCmd(client *api.Client, source string, lang Language) tea.Cmd {
	return func() tea.Msg {
		result, err := client.Init(source, defaultPacket, lang.String())
		if err != nil {
			return errMsg{err: err}
		}
		return initResultMsg{result: result}
	}
}

func stepCmd(client *api.Client, sessionID string) tea.Cmd {
	return func() tea.Msg {
		state, err := client.Step(sessionID)
		if err != nil {
			return errMsg{err: err}
		}
		return stepResultMsg{state: state}
	}
}

func runCmd(client *api.Client, sessionID string) tea.Cmd {
	return func() tea.Msg {
		state, err := client.Run(sessionID)
		if err != nil {
			return errMsg{err: err}
		}
		return runResultMsg{state: state}
	}
}

func resetCmd(client *api.Client, sessionID string) tea.Cmd {
	return func() tea.Msg {
		state, err := client.Reset(sessionID, defaultPacket)
		if err != nil {
			return errMsg{err: err}
		}
		return resetResultMsg{state: state}
	}
}

func loadExampleCmd(client *api.Client, name string) tea.Cmd {
	return func() tea.Msg {
		source, err := client.LoadExample(name)
		if err != nil {
			return errMsg{err: err}
		}
		return exampleLoadedMsg{source: source}
	}
}

// LoadFile loads source from a file path.
func LoadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
