package highlight

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
)

var (
	keywordStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("90"))  // dark magenta
	typeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("25"))  // dark blue
	actionStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("130")) // dark orange
	builtinStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("30"))  // dark cyan
	numberStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("28"))  // dark green
	commentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("242")) // gray
	stringStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("130")) // dark orange
)

var keywords = map[string]bool{
	"xdp": true, "fn": true, "do": true, "end": true, "return": true,
	"if": true, "elif": true, "else": true, "for": true, "let": true,
	"match": true, "map": true, "break": true, "continue": true,
	"in": true, "and": true, "or": true, "not": true, "def": true,
}

var types = map[string]bool{
	"u8": true, "u16": true, "u32": true, "u64": true,
	"i8": true, "i16": true, "i32": true, "i64": true,
	"bool": true, "action": true,
}

var builtins = map[string]bool{
	"map_lookup": true, "map_update": true, "map_delete": true,
	"read_u8": true, "read_u16_be": true, "read_u32_be": true,
	"read_u16_le": true, "read_u32_le": true, "ctx": true,
}

// Highlight colorizes a single line of EBL source code.
func Highlight(line string) string {
	// Handle full-line comments
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") {
		return commentStyle.Render(line)
	}

	var result strings.Builder
	runes := []rune(line)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		// Comment to end of line
		if ch == '/' && i+1 < len(runes) && runes[i+1] == '/' {
			result.WriteString(commentStyle.Render(string(runes[i:])))
			return result.String()
		}

		// Block comment start
		if ch == '/' && i+1 < len(runes) && runes[i+1] == '*' {
			end := strings.Index(string(runes[i+2:]), "*/")
			if end >= 0 {
				result.WriteString(commentStyle.Render(string(runes[i : i+2+end+2])))
				i += 2 + end + 2
			} else {
				result.WriteString(commentStyle.Render(string(runes[i:])))
				return result.String()
			}
			continue
		}

		// String literal
		if ch == '"' {
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				if runes[j] == '\\' && j+1 < len(runes) {
					j++
				}
				j++
			}
			if j < len(runes) {
				j++ // include closing quote
			}
			result.WriteString(stringStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Action atoms (:word)
		if ch == ':' && i+1 < len(runes) && unicode.IsLetter(runes[i+1]) {
			j := i + 1
			for j < len(runes) && (unicode.IsLetter(runes[j]) || runes[j] == '_') {
				j++
			}
			result.WriteString(actionStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Hex numbers
		if ch == '0' && i+1 < len(runes) && (runes[i+1] == 'x' || runes[i+1] == 'X') {
			j := i + 2
			for j < len(runes) && isHexDigit(runes[j]) {
				j++
			}
			result.WriteString(numberStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Decimal numbers
		if unicode.IsDigit(ch) {
			j := i
			for j < len(runes) && unicode.IsDigit(runes[j]) {
				j++
			}
			result.WriteString(numberStyle.Render(string(runes[i:j])))
			i = j
			continue
		}

		// Identifiers / keywords
		if unicode.IsLetter(ch) || ch == '_' {
			j := i
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_') {
				j++
			}
			word := string(runes[i:j])
			if keywords[word] {
				result.WriteString(keywordStyle.Render(word))
			} else if types[word] {
				result.WriteString(typeStyle.Render(word))
			} else if builtins[word] {
				result.WriteString(builtinStyle.Render(word))
			} else {
				result.WriteString(word)
			}
			i = j
			continue
		}

		// Arrows and operators
		if ch == '-' && i+1 < len(runes) && runes[i+1] == '>' {
			result.WriteString(keywordStyle.Render("->"))
			i += 2
			continue
		}

		result.WriteRune(ch)
		i++
	}

	return result.String()
}

func isHexDigit(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
