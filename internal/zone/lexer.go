package zone

import (
	"fmt"
	"strings"
)

// Entry is one logical master-file entry: a single record line or a
// directive, after comments are stripped and parenthesised continuations are
// joined.
type Entry struct {
	// Line is the 1-based source line where the entry starts.
	Line int
	// Text is the entry with comments removed, parentheses removed and
	// whitespace normalised to single spaces. It is non-empty.
	Text string
	// LeadingSpace reports whether the first physical line of the entry
	// began with whitespace, which is how a blank (inherited) owner is
	// expressed in master-file syntax.
	LeadingSpace bool
}

// ParseError is an unrecoverable lexer or parser error.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.File, e.Msg)
}

// Lex splits master-file source into logical entries.
//
// It strips `;` comments (except inside quoted strings), joins lines wrapped
// in parentheses and normalises whitespace. Unbalanced parentheses or an
// unterminated quoted string at end of input are unrecoverable errors.
func Lex(file, src string) ([]Entry, error) {
	var (
		entries   []Entry
		buf       []byte
		depth     int
		inQuote   bool
		escaped   bool
		startLine int
		leading   bool
	)

	space := func() {
		if len(buf) > 0 && buf[len(buf)-1] != ' ' {
			buf = append(buf, ' ')
		}
	}
	flush := func(line int) {
		text := strings.TrimSpace(string(buf))
		buf = buf[:0]
		if text != "" {
			entries = append(entries, Entry{Line: line, Text: text, LeadingSpace: leading})
		}
	}

	lines := strings.Split(src, "\n")
	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSuffix(raw, "\r")
		if depth == 0 && !inQuote && len(buf) == 0 {
			startLine = lineNo
			leading = line != "" && (line[0] == ' ' || line[0] == '\t')
		}

		for j := 0; j < len(line); j++ {
			c := line[j]
			if escaped {
				buf = append(buf, c)
				escaped = false
				continue
			}
			if inQuote {
				switch c {
				case '\\':
					buf = append(buf, c)
					escaped = true
				case '"':
					buf = append(buf, c)
					inQuote = false
				default:
					buf = append(buf, c)
				}
				continue
			}
			switch c {
			case '\\':
				buf = append(buf, c)
			case '"':
				buf = append(buf, c)
				inQuote = true
			case ';':
				j = len(line) // comment: drop the rest of the line
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return nil, &ParseError{File: file, Line: lineNo, Msg: "unbalanced closing parenthesis"}
				}
			case ' ', '\t':
				space()
			default:
				buf = append(buf, c)
			}
		}

		if inQuote {
			// A quoted string may continue on the next physical line; the
			// newline becomes a single space.
			space()
			continue
		}
		if depth > 0 {
			// Inside parentheses the newline is a soft break.
			space()
			continue
		}
		flush(startLine)
	}

	if inQuote {
		return nil, &ParseError{File: file, Line: startLine, Msg: "unterminated quoted string"}
	}
	if depth > 0 {
		return nil, &ParseError{File: file, Line: startLine, Msg: "unbalanced opening parenthesis"}
	}
	flush(startLine)
	return entries, nil
}

// tokenize splits a logical entry into tokens, honouring double-quoted
// strings with \" and \\ escapes. A token may mix quoted and unquoted parts
// (abc"def"ghi is one token).
func tokenize(text string) ([]string, error) {
	var (
		tokens []string
		cur    strings.Builder
		inTok  bool
		inQ    bool
		esc    bool
	)
	flush := func() {
		if inTok {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inQ {
			inTok = true
			switch {
			case esc:
				cur.WriteByte(c)
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inQ = false
			default:
				cur.WriteByte(c)
			}
			continue
		}
		switch c {
		case '"':
			inQ = true
			inTok = true
		case ' ', '\t':
			flush()
		default:
			cur.WriteByte(c)
			inTok = true
		}
	}
	if inQ {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	flush()
	return tokens, nil
}
