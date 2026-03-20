package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/erlkoenig/erlkoenig_bpf_tui/internal/highlight"
)

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("19"))

	focusedBorderColor = lipgloss.Color("19")
	normalBorderColor  = lipgloss.Color("240")

	pcHighlightStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("229")).
				Foreground(lipgloss.Color("0"))

	srcHighlightStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("194")).
				Foreground(lipgloss.Color("0"))

	regChangedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("28")).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("124")).
			Bold(true)

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("252"))

	statusBarKeyStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(lipgloss.Color("214")).
				Bold(true)

	dimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
)

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	if m.showHelp {
		return m.renderHelp()
	}

	// Calculate panel widths
	totalW := m.width
	sourceW := totalW * 35 / 100
	disasmW := totalW * 35 / 100
	regW := totalW - sourceW - disasmW
	if regW < 20 {
		regW = 20
	}

	contentH := m.contentHeight()

	// Render panels
	srcTitle := fmt.Sprintf("SOURCE [%s]", m.language.Label())
	srcPanel := m.renderPanel(srcTitle, panelSource, sourceW, contentH, m.renderSource(sourceW-4, contentH))
	disPanel := m.renderPanel("DISASSEMBLY", panelDisasm, disasmW, contentH, m.renderDisasm(disasmW-4, contentH))

	// Right side: registers (top) + maps (bottom)
	regContent, mapContent := m.renderRegsAndMaps(regW-4, contentH)
	regH := contentH * 2 / 3
	mapH := contentH - regH
	regPanel := m.renderPanel("REGISTERS", panelRegisters, regW, regH, regContent)
	mapPanel := m.renderSubPanel("MAPS", regW, mapH, mapContent)
	rightSide := lipgloss.JoinVertical(lipgloss.Left, regPanel, mapPanel)

	// Join panels horizontally
	panels := lipgloss.JoinHorizontal(lipgloss.Top, srcPanel, disPanel, rightSide)

	// Status bar
	statusBar := m.renderStatusBar(totalW)

	return lipgloss.JoinVertical(lipgloss.Left, panels, statusBar)
}

func (m Model) renderPanel(title string, p panel, width, height int, content string) string {
	borderColor := normalBorderColor
	if m.focus == p {
		borderColor = focusedBorderColor
	}

	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Width(width - 2).
		Height(height)

	header := headerStyle.Render(fmt.Sprintf(" %s ", title))
	body := lipgloss.JoinVertical(lipgloss.Left, header, content)
	return style.Render(body)
}

func (m Model) renderSubPanel(title string, width, height int, content string) string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(normalBorderColor).
		Width(width - 2).
		Height(height)

	header := headerStyle.Render(fmt.Sprintf(" %s ", title))
	body := lipgloss.JoinVertical(lipgloss.Left, header, content)
	return style.Render(body)
}

func (m Model) renderSource(width, height int) string {
	if len(m.sourceLines) == 0 {
		return dimStyle.Render("  No source loaded\n  Press 1-9 to load an example\n  or start with --file <path>")
	}

	// Determine which source line is linked to current PC
	highlightLine := -1
	if m.state != nil && m.sourceMap != nil {
		if loc, ok := m.sourceMap[m.state.PC]; ok {
			highlightLine = loc[0] - 1 // 1-indexed to 0-indexed
		}
	}

	var lines []string
	end := m.sourceScroll + height - 1 // -1 for header
	if end > len(m.sourceLines) {
		end = len(m.sourceLines)
	}

	for i := m.sourceScroll; i < end; i++ {
		lineNum := fmt.Sprintf("%3d ", i+1)
		lineText := m.sourceLines[i]

		// Truncate if too wide
		maxTextW := width - 5
		if maxTextW < 10 {
			maxTextW = 10
		}
		if len(lineText) > maxTextW {
			lineText = lineText[:maxTextW]
		}

		var highlighted string
		if m.language == LangElixir {
			highlighted = highlight.HighlightElixir(lineText)
		} else {
			highlighted = highlight.Highlight(lineText)
		}

		if i == highlightLine {
			// Highlight the source line linked to current PC
			line := dimStyle.Render(lineNum) + srcHighlightStyle.Render(padRight(lineText, maxTextW))
			lines = append(lines, line)
		} else if m.editing && i == m.cursorLine {
			// Show cursor in edit mode
			var cursorLine string
			if m.cursorCol < len(lineText) {
				cursorLine = lineText[:m.cursorCol] + "\u2588" + lineText[m.cursorCol+1:]
			} else {
				cursorLine = lineText + "\u2588"
			}
			lines = append(lines, dimStyle.Render(lineNum)+cursorLine)
		} else {
			lines = append(lines, dimStyle.Render(lineNum)+highlighted)
		}
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderDisasm(width, height int) string {
	if len(m.instructions) == 0 {
		if m.compiled {
			return dimStyle.Render("  No instructions")
		}
		return dimStyle.Render("  Press F5 to compile")
	}

	currentPC := -1
	if m.state != nil {
		currentPC = m.state.PC
	}

	var lines []string
	end := m.disasmScroll + height - 1
	if end > len(m.instructions) {
		end = len(m.instructions)
	}

	for i := m.disasmScroll; i < end; i++ {
		insn := m.instructions[i]
		marker := "  "
		if insn.PC == currentPC {
			marker = "\u25b6 "
		}

		line := fmt.Sprintf("%s%3d: %s", marker, insn.PC, insn.Text)

		maxW := width
		if len(line) > maxW {
			line = line[:maxW]
		}

		if insn.PC == currentPC {
			lines = append(lines, pcHighlightStyle.Render(padRight(line, maxW)))
		} else {
			lines = append(lines, line)
		}
	}

	return strings.Join(lines, "\n")
}

func (m Model) renderRegsAndMaps(width, height int) (string, string) {
	// Registers
	var regLines []string
	if m.state != nil && len(m.state.Registers) > 0 {
		for _, reg := range m.state.Registers {
			label := fmt.Sprintf("R%-2d ", reg.Index)
			val := reg.Value

			// Check if changed
			changed := false
			if m.prevRegs != nil {
				for _, prev := range m.prevRegs {
					if prev.Index == reg.Index && prev.Value != val {
						changed = true
						break
					}
				}
			}

			line := fmt.Sprintf("%s %s", label, val)
			if changed {
				regLines = append(regLines, regChangedStyle.Render(line))
			} else {
				regLines = append(regLines, line)
			}
		}
	} else {
		regLines = append(regLines, dimStyle.Render("  No state"))
	}

	// Stack (if any, append after registers)
	if m.state != nil && len(m.state.Stack) > 0 {
		regLines = append(regLines, "")
		regLines = append(regLines, dimStyle.Render("Stack:"))
		for _, slot := range m.state.Stack {
			regLines = append(regLines, fmt.Sprintf("  [%d] %s", slot.Offset, slot.Value))
		}
	}

	// Maps
	var mapLines []string
	if m.state != nil && len(m.state.Maps) > 0 {
		for _, mp := range m.state.Maps {
			header := fmt.Sprintf("#%d %s (%d\u2192%d) %d ent",
				mp.FD, mp.Type, mp.KeySize, mp.ValueSize, len(mp.Entries))
			mapLines = append(mapLines, header)
			// Show first few entries
			for i, entry := range mp.Entries {
				if i >= 3 {
					mapLines = append(mapLines, dimStyle.Render(fmt.Sprintf("  ... +%d more", len(mp.Entries)-3)))
					break
				}
				mapLines = append(mapLines, fmt.Sprintf("  %s \u2192 %s", entry.Key, entry.Value))
			}
		}
	} else if m.mapSpecs != nil && len(m.mapSpecs) > 0 {
		for _, ms := range m.mapSpecs {
			mapLines = append(mapLines, fmt.Sprintf("#%d %s (%d\u2192%d)",
				ms.FD, ms.Type, ms.KeySize, ms.ValueSize))
		}
	} else {
		mapLines = append(mapLines, dimStyle.Render("  No maps"))
	}

	return strings.Join(regLines, "\n"), strings.Join(mapLines, "\n")
}

func (m Model) renderStatusBar(width int) string {
	// Line 1: key bindings
	keys := []struct{ key, desc string }{
		{"F5", "compile"},
		{"F8", "run"},
		{"F10", "step"},
		{"F6", "reset"},
		{"n", "step"},
		{"r", "reset"},
		{"L", m.language.Label()},
		{"Tab", "focus"},
		{"e", "edit"},
		{"?", "help"},
		{"q", "quit"},
	}

	var keyParts []string
	for _, k := range keys {
		keyParts = append(keyParts, statusBarKeyStyle.Render(k.key)+statusBarStyle.Render(":"+k.desc))
	}
	keyLine := strings.Join(keyParts, statusBarStyle.Render("  "))
	keyLine = statusBarStyle.Width(width).Render(keyLine)

	// Line 2: session status
	var infoParts []string
	if m.connected {
		infoParts = append(infoParts, lipgloss.NewStyle().Foreground(lipgloss.Color("28")).Render("\u25cf connected"))
	} else {
		infoParts = append(infoParts, lipgloss.NewStyle().Foreground(lipgloss.Color("124")).Render("\u25cf disconnected"))
	}

	if m.state != nil {
		infoParts = append(infoParts, fmt.Sprintf("Status: %s", m.state.Status))
		infoParts = append(infoParts, fmt.Sprintf("PC: %d", m.state.PC))
		infoParts = append(infoParts, fmt.Sprintf("Steps: %d/%d", m.state.InsnExecuted, m.state.InsnCount))
		if m.state.Result != nil {
			infoParts = append(infoParts, fmt.Sprintf("Result: %d", *m.state.Result))
		}
	}

	if m.editing {
		infoParts = append(infoParts, lipgloss.NewStyle().Foreground(lipgloss.Color("130")).Bold(true).Render("[EDIT]"))
	}

	if m.statusMsg != "" && m.err == "" {
		infoParts = append(infoParts, m.statusMsg)
	}

	infoLine := statusBarStyle.Width(width).Render(strings.Join(infoParts, " | "))

	// Line 3: error OR examples (full width, prominently visible)
	var line3 string
	if m.err != "" {
		errMsg := m.err
		maxLen := width - 4
		if len(errMsg) > maxLen {
			errMsg = errMsg[:maxLen]
		}
		errBar := lipgloss.NewStyle().
			Background(lipgloss.Color("124")).
			Foreground(lipgloss.Color("15")).
			Bold(true).
			Width(width).
			Render(" \u2718 " + errMsg)
		line3 = errBar
	} else {
		// Show examples hint for current language
		var activeExamples []string
		if m.language == LangElixir {
			activeExamples = m.elixirExamples
		} else {
			activeExamples = m.eblExamples
		}
		if len(activeExamples) > 0 && !m.compiled {
			exHint := " Examples: "
			for i, name := range activeExamples {
				if i >= 9 {
					break
				}
				if i > 0 {
					exHint += "  "
				}
				exHint += fmt.Sprintf("%d:%s", i+1, name)
			}
			line3 = statusBarStyle.Width(width).Render(dimStyle.Render(exHint))
		} else {
			line3 = statusBarStyle.Width(width).Render("")
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, keyLine, infoLine, line3)
}

func (m Model) renderHelp() string {
	help := `
  Erlkoenig BPF Compiler Explorer
  ================================

  Key Bindings:

  F5 / Ctrl+B     Compile source and init debugger session
  F8 / Ctrl+R     Run to completion
  F10 / Ctrl+N    Single step
  F6 / Ctrl+E     Reset execution
  Tab / Shift+Tab  Cycle panel focus
  j/k / Up/Down   Scroll in focused panel
  g / G           Scroll to top / bottom
  e               Enter edit mode (source panel)
  Esc             Exit edit mode / close help
  1-9             Load example by number
  ?               Toggle this help
  q / Ctrl+C      Quit

  The TUI connects to the erlkoenig_bpf debugger backend
  at the configured address (default: localhost:8080).

  Start the backend with: make explorer (in erlkoenig_bpf)

  Press ? or Esc to close this help.
`
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("19")).
		Padding(1, 2).
		Width(m.width - 4).
		Height(m.height - 4)

	return style.Render(help)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
