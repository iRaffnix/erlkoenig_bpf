package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/erlkoenig/erlkoenig_bpf_tui/internal/api"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case errMsg:
		m.err = msg.Error()
		m.statusMsg = ""
		return m, nil

	case statusMsg:
		m.connected = true
		m.statusMsg = msg.msg
		m.err = ""
		return m, nil

	case examplesMsg:
		m.eblExamples = msg.eblExamples
		m.elixirExamples = msg.elixirExamples
		return m, nil

	case exampleLoadedMsg:
		m.source = msg.source
		m.sourceLines = strings.Split(m.source, "\n")
		m.compiled = false
		m.state = nil
		m.sessionID = ""
		m.instructions = nil
		m.sourceMap = nil
		m.err = ""
		m.sourceScroll = 0
		m.statusMsg = "Example loaded"
		return m, nil

	case initResultMsg:
		r := msg.result
		m.sessionID = r.SessionID
		m.instructions = r.Instructions
		m.ir = r.IR
		m.state = &r.State
		m.prevRegs = nil
		m.mapSpecs = r.MapSpecs
		m.compiled = true
		m.err = ""
		m.disasmScroll = 0
		// Convert source map
		m.sourceMap = make(map[int][2]int)
		for k, v := range r.SourceMap {
			var pc int
			fmt.Sscanf(k, "%d", &pc)
			m.sourceMap[pc] = v
		}
		m.statusMsg = fmt.Sprintf("Compiled: %d instructions", r.State.InsnCount)
		return m, nil

	case stepResultMsg:
		m.prevRegs = copyRegs(m.state)
		m.state = msg.state
		m.err = ""
		m.autoScrollDisasm()
		m.statusMsg = ""
		return m, nil

	case runResultMsg:
		m.prevRegs = copyRegs(m.state)
		m.state = msg.state
		m.err = ""
		m.autoScrollDisasm()
		m.statusMsg = ""
		return m, nil

	case resetResultMsg:
		m.prevRegs = nil
		m.state = msg.state
		m.err = ""
		m.disasmScroll = 0
		m.statusMsg = "Reset"
		return m, nil
	}

	return m, nil
}

func copyRegs(state *api.VMState) []api.Register {
	if state == nil {
		return nil
	}
	regs := make([]api.Register, len(state.Registers))
	copy(regs, state.Registers)
	return regs
}

func (m *Model) autoScrollDisasm() {
	if m.state == nil {
		return
	}
	contentHeight := m.contentHeight()
	if contentHeight <= 0 {
		contentHeight = 20
	}
	pc := m.state.PC
	// Keep current PC visible in disassembly panel
	if pc < m.disasmScroll {
		m.disasmScroll = pc
	} else if pc >= m.disasmScroll+contentHeight-2 {
		m.disasmScroll = pc - contentHeight/2
	}
	if m.disasmScroll < 0 {
		m.disasmScroll = 0
	}
}

func (m *Model) contentHeight() int {
	// Total height minus status bar (3 lines) minus panel header (1 line) minus border
	h := m.height - 5
	if h < 5 {
		h = 5
	}
	return h
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global keys (always active)
	switch key {
	case "ctrl+c":
		return m, tea.Quit
	case "q":
		if !m.editing {
			return m, tea.Quit
		}
	case "?":
		if !m.editing {
			m.showHelp = !m.showHelp
			return m, nil
		}
	}

	// Edit mode keys
	if m.editing {
		return m.handleEditKey(msg)
	}

	switch msg.Type {
	case tea.KeyF5:
		return m.doCompile()
	case tea.KeyF8:
		return m.doRun()
	case tea.KeyF10:
		return m.doStep()
	case tea.KeyF6:
		return m.doReset()
	}

	switch key {
	// Compile + Init (keyboard alternatives)
	case "ctrl+b":
		return m.doCompile()

	// Run
	case "ctrl+r":
		return m.doRun()

	// Step
	case "ctrl+n", "n":
		return m.doStep()

	// Reset
	case "ctrl+e", "r":
		return m.doReset()

	// Focus cycling
	case "tab":
		m.focus = (m.focus + 1) % 3
		return m, nil
	case "shift+tab":
		m.focus = (m.focus + 2) % 3
		return m, nil

	// Scrolling
	case "j", "down":
		m.scrollDown()
		return m, nil
	case "k", "up":
		m.scrollUp()
		return m, nil
	case "g":
		m.scrollToTop()
		return m, nil
	case "G":
		m.scrollToBottom()
		return m, nil

	// Edit mode
	case "e":
		m.editing = true
		m.cursorLine = 0
		m.cursorCol = 0
		m.statusMsg = "Editing — Esc to finish"
		return m, nil

	// Toggle language
	case "l", "L":
		if m.language == LangEBL {
			m.language = LangElixir
		} else {
			m.language = LangEBL
		}
		m.compiled = false
		m.state = nil
		m.sessionID = ""
		m.instructions = nil
		m.statusMsg = fmt.Sprintf("Language: %s", m.language.Label())
		return m, nil

	// Load examples by number
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(msg.String()[0] - '1')
		if m.language == LangElixir {
			if idx < len(m.elixirExamples) {
				name := m.elixirExamples[idx]
				m.statusMsg = fmt.Sprintf("Loading DSL: %s", name)
				return m, loadDSLFileCmd(m.dslDir, name)
			}
		} else {
			if idx < len(m.eblExamples) {
				m.statusMsg = fmt.Sprintf("Loading: %s", m.eblExamples[idx])
				return m, loadExampleCmd(m.client, m.eblExamples[idx])
			}
		}
		return m, nil
	}

	return m, nil
}

func (m Model) handleEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editing = false
		m.statusMsg = ""
		return m, nil

	case "enter":
		// Insert newline
		lines := m.sourceLines
		if m.cursorLine < len(lines) {
			line := lines[m.cursorLine]
			before := line
			after := ""
			if m.cursorCol < len(line) {
				before = line[:m.cursorCol]
				after = line[m.cursorCol:]
			}
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:m.cursorLine]...)
			newLines = append(newLines, before, after)
			if m.cursorLine+1 < len(lines) {
				newLines = append(newLines, lines[m.cursorLine+1:]...)
			}
			m.sourceLines = newLines
			m.cursorLine++
			m.cursorCol = 0
		}
		m.source = strings.Join(m.sourceLines, "\n")
		m.compiled = false
		return m, nil

	case "backspace":
		if m.cursorCol > 0 && m.cursorLine < len(m.sourceLines) {
			line := m.sourceLines[m.cursorLine]
			if m.cursorCol <= len(line) {
				m.sourceLines[m.cursorLine] = line[:m.cursorCol-1] + line[m.cursorCol:]
				m.cursorCol--
			}
		} else if m.cursorCol == 0 && m.cursorLine > 0 {
			// Join with previous line
			prevLine := m.sourceLines[m.cursorLine-1]
			m.cursorCol = len(prevLine)
			m.sourceLines[m.cursorLine-1] = prevLine + m.sourceLines[m.cursorLine]
			m.sourceLines = append(m.sourceLines[:m.cursorLine], m.sourceLines[m.cursorLine+1:]...)
			m.cursorLine--
		}
		m.source = strings.Join(m.sourceLines, "\n")
		m.compiled = false
		return m, nil

	case "left":
		if m.cursorCol > 0 {
			m.cursorCol--
		}
		return m, nil
	case "right":
		if m.cursorLine < len(m.sourceLines) && m.cursorCol < len(m.sourceLines[m.cursorLine]) {
			m.cursorCol++
		}
		return m, nil
	case "up":
		if m.cursorLine > 0 {
			m.cursorLine--
			if m.cursorLine < len(m.sourceLines) && m.cursorCol > len(m.sourceLines[m.cursorLine]) {
				m.cursorCol = len(m.sourceLines[m.cursorLine])
			}
		}
		return m, nil
	case "down":
		if m.cursorLine < len(m.sourceLines)-1 {
			m.cursorLine++
			if m.cursorCol > len(m.sourceLines[m.cursorLine]) {
				m.cursorCol = len(m.sourceLines[m.cursorLine])
			}
		}
		return m, nil

	default:
		// Insert character
		r := msg.String()
		if len(r) == 1 && r[0] >= 32 && r[0] < 127 {
			if m.cursorLine >= len(m.sourceLines) {
				m.sourceLines = append(m.sourceLines, "")
			}
			line := m.sourceLines[m.cursorLine]
			if m.cursorCol > len(line) {
				m.cursorCol = len(line)
			}
			m.sourceLines[m.cursorLine] = line[:m.cursorCol] + r + line[m.cursorCol:]
			m.cursorCol++
			m.source = strings.Join(m.sourceLines, "\n")
			m.compiled = false
		}
		return m, nil
	}
}

func (m Model) doCompile() (tea.Model, tea.Cmd) {
	if m.source == "" {
		m.err = "No source to compile"
		return m, nil
	}
	if !m.connected {
		m.err = "Backend not connected — start with: cd erlkoenig_bpf && make explorer"
		return m, nil
	}
	m.statusMsg = "Compiling..."
	m.err = ""
	return m, compileAndInitCmd(m.client, m.source, m.language)
}

func (m Model) doRun() (tea.Model, tea.Cmd) {
	if m.sessionID == "" {
		m.err = "No active session — compile first (F5)"
		return m, nil
	}
	if m.state != nil && m.state.Status == "halted" {
		m.err = "Program halted — reset first (F6)"
		return m, nil
	}
	m.statusMsg = "Running..."
	return m, runCmd(m.client, m.sessionID)
}

func (m Model) doStep() (tea.Model, tea.Cmd) {
	if m.sessionID == "" {
		m.err = "No active session — compile first (F5)"
		return m, nil
	}
	if m.state != nil && m.state.Status == "halted" {
		m.err = "Program halted — reset first (F6)"
		return m, nil
	}
	return m, stepCmd(m.client, m.sessionID)
}

func (m Model) doReset() (tea.Model, tea.Cmd) {
	if m.sessionID == "" {
		m.err = "No active session — compile first (F5)"
		return m, nil
	}
	return m, resetCmd(m.client, m.sessionID)
}

func (m *Model) scrollDown() {
	switch m.focus {
	case panelSource:
		maxScroll := len(m.sourceLines) - m.contentHeight()
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.sourceScroll < maxScroll {
			m.sourceScroll++
		}
	case panelDisasm:
		maxScroll := len(m.instructions) - m.contentHeight()
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.disasmScroll < maxScroll {
			m.disasmScroll++
		}
	case panelRegisters:
		if m.regScroll < 10 {
			m.regScroll++
		}
	}
}

func (m *Model) scrollUp() {
	switch m.focus {
	case panelSource:
		if m.sourceScroll > 0 {
			m.sourceScroll--
		}
	case panelDisasm:
		if m.disasmScroll > 0 {
			m.disasmScroll--
		}
	case panelRegisters:
		if m.regScroll > 0 {
			m.regScroll--
		}
	}
}

func (m *Model) scrollToTop() {
	switch m.focus {
	case panelSource:
		m.sourceScroll = 0
	case panelDisasm:
		m.disasmScroll = 0
	case panelRegisters:
		m.regScroll = 0
	}
}

func (m *Model) scrollToBottom() {
	switch m.focus {
	case panelSource:
		max := len(m.sourceLines) - m.contentHeight()
		if max < 0 {
			max = 0
		}
		m.sourceScroll = max
	case panelDisasm:
		max := len(m.instructions) - m.contentHeight()
		if max < 0 {
			max = 0
		}
		m.disasmScroll = max
	}
}

func loadDSLFileCmd(dir, name string) tea.Cmd {
	return func() tea.Msg {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return errMsg{err: fmt.Errorf("load DSL %s: %w", name, err)}
		}
		return exampleLoadedMsg{source: string(data)}
	}
}
