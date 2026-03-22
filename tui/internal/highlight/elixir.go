package highlight

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
)

var (
	exKeywordStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("90"))  // dark magenta
	exModuleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("25"))  // dark blue
	exAtomStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("130")) // dark orange
	exFuncStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("30"))  // dark cyan
	exNumberStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("28"))  // dark green
	exCommentStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("242")) // gray
	exStringStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("130")) // dark orange
	exVariableStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("238")) // dark
)

var exKeywords = map[string]bool{
	"defmodule": true, "def": true, "defp": true, "do": true, "end": true,
	"if": true, "else": true, "case": true, "cond": true, "when": true,
	"fn": true, "use": true, "import": true, "alias": true, "require": true,
	"and": true, "or": true, "not": true, "in": true, "true": true, "false": true,
	"nil": true, "with": true, "for": true, "unless": true, "raise": true,
}

var exDSLKeywords = map[string]bool{
	"xdp": true, "map": true, "on_tcp": true, "on_udp": true, "on_icmp": true,
	"on_ipv4": true, "on_ipv6": true, "on_arp": true, "on_dns": true,
	"on_tcp6": true, "on_udp6": true, "on_vlan_ipv4": true, "on_vlan_tcp": true,
}

var exBuiltins = map[string]bool{
	"map_lookup": true, "map_update": true, "map_delete": true,
	"is_syn": true, "is_ack": true, "is_fin": true, "is_rst": true,
	"src_ip": true, "dst_ip": true, "src_port": true, "dst_port": true,
	"protocol": true, "ttl": true, "total_length": true, "udp_length": true,
	"icmp_type": true, "icmp_code": true, "sender_ip": true, "target_ip": true,
	"arp_op": true, "ingress_ifindex": true,
}

// HighlightElixir colorizes a single line of Elixir/DSL source code.
func HighlightElixir(line string) string {
	trimmed := strings.TrimSpace(line)

	// Full-line comment
	if strings.HasPrefix(trimmed, "#") {
		return exCommentStyle.Render(line)
	}

	var result strings.Builder
	runes := []rune(line)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		// Comment to end of line
		if ch == '#' {
			result.WriteString(exCommentStyle.Render(string(runes[i:])))
			return result.String()
		}

		// String literal (double-quoted)
		if ch == '"' {
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' && j+1 < len(runes) {
					j++
				}
				j++
			}
			if j < len(runes) {
				j++
			}
			result.WriteString(exStringStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Atom (:word or :word_with_underscores)
		if ch == ':' && i+1 < len(runes) && (unicode.IsLetter(runes[i+1]) || runes[i+1] == '_') {
			j := i + 1
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_') {
				j++
			}
			result.WriteString(exAtomStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Hex numbers
		if ch == '0' && i+1 < len(runes) && (runes[i+1] == 'x' || runes[i+1] == 'X') {
			j := i + 2
			for j < len(runes) && isHexDigit(runes[j]) {
				j++
			}
			result.WriteString(exNumberStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Decimal numbers
		if unicode.IsDigit(ch) {
			j := i
			for j < len(runes) && (unicode.IsDigit(runes[j]) || runes[j] == '_') {
				j++
			}
			result.WriteString(exNumberStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Module names (uppercase start)
		if unicode.IsUpper(ch) {
			j := i
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '.') {
				j++
			}
			result.WriteString(exModuleStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Identifiers / keywords
		if unicode.IsLetter(ch) || ch == '_' {
			j := i
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_' || runes[j] == '!' || runes[j] == '?') {
				j++
			}
			word := string(runes[i:j])
			if exKeywords[word] {
				result.WriteString(exKeywordStyle.Render(word))
			} else if exDSLKeywords[word] {
				result.WriteString(exKeywordStyle.Render(word))
			} else if exBuiltins[word] {
				result.WriteString(exFuncStyle.Render(word))
			} else {
				result.WriteString(exVariableStyle.Render(word))
			}
			i = j
			continue
		}

		// Arrow
		if ch == '-' && i+1 < len(runes) && runes[i+1] == '>' {
			result.WriteString(exKeywordStyle.Render("->"))
			i += 2
			continue
		}

		// Pipe
		if ch == '|' && i+1 < len(runes) && runes[i+1] == '>' {
			result.WriteString(exKeywordStyle.Render("|>"))
			i += 2
			continue
		}

		result.WriteRune(ch)
		i++
	}

	return result.String()
}
