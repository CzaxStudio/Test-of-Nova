package main

import (
	"fmt"
	"strings"
	"unicode"
)

type TokenType int

const (
	TOKEN_IDENT   TokenType = iota
	TOKEN_STRING            // "hello"
	TOKEN_FSTRING           // f"hello {name}"
	TOKEN_NUMBER
	TOKEN_BOOL
	TOKEN_NIL
	TOKEN_DO
	TOKEN_TRACE
	TOKEN_CAPTURE
	TOKEN_COMPUTE
	TOKEN_IMPORT
	TOKEN_LET
	TOKEN_IF
	TOKEN_ELSEIF
	TOKEN_ELSE
	TOKEN_LOOP
	TOKEN_FUNC
	TOKEN_RETURN
	TOKEN_BREAK
	TOKEN_CONTINUE
	TOKEN_EACH
	TOKEN_TRY
	TOKEN_CATCH
	TOKEN_MATCH
	TOKEN_SPAWN
	TOKEN_FATARROW // =>
	TOKEN_WILDCARD // _
	TOKEN_ARROW    // -->
	TOKEN_ASSIGN
	TOKEN_PLUS_EQ  // +=
	TOKEN_MINUS_EQ // -=
	TOKEN_PLUS
	TOKEN_MINUS
	TOKEN_STAR
	TOKEN_SLASH
	TOKEN_PERCENT
	TOKEN_EQ
	TOKEN_NEQ
	TOKEN_LT
	TOKEN_GT
	TOKEN_LTE
	TOKEN_GTE
	TOKEN_AND
	TOKEN_OR
	TOKEN_NOT
	TOKEN_PIPE
	TOKEN_LPAREN
	TOKEN_RPAREN
	TOKEN_LBRACE
	TOKEN_RBRACE
	TOKEN_LBRACKET
	TOKEN_RBRACKET
	TOKEN_COMMA
	TOKEN_COLON
	TOKEN_DOT
	TOKEN_RUNNER // # runner<?...>  — the command is stored in Value
	TOKEN_NEWLINE
	TOKEN_EOF
)

var keywords = map[string]TokenType{
	"do":       TOKEN_DO,
	"Trace":    TOKEN_TRACE,
	"Capture":  TOKEN_CAPTURE,
	"Compute":  TOKEN_COMPUTE,
	"let":      TOKEN_LET,
	"if":       TOKEN_IF,
	"elseif":   TOKEN_ELSEIF,
	"else":     TOKEN_ELSE,
	"loop":     TOKEN_LOOP,
	"func":     TOKEN_FUNC,
	"return":   TOKEN_RETURN,
	"break":    TOKEN_BREAK,
	"continue": TOKEN_CONTINUE,
	"each":     TOKEN_EACH,
	"try":      TOKEN_TRY,
	"catch":    TOKEN_CATCH,
	"match":    TOKEN_MATCH,
	"spawn":    TOKEN_SPAWN,
	"true":     TOKEN_BOOL,
	"false":    TOKEN_BOOL,
	"nil":      TOKEN_NIL,
	"_":        TOKEN_WILDCARD,
}

type Token struct {
	Type  TokenType
	Value string
	Line  int
	Col   int
}

type Lexer struct {
	source []rune
	pos    int
	line   int
	col    int
	tokens []Token
}

func NewLexer(src string) *Lexer {
	return &Lexer{source: []rune(src), pos: 0, line: 1, col: 1}
}

func (l *Lexer) peek() rune {
	if l.pos >= len(l.source) {
		return 0
	}
	return l.source[l.pos]
}
func (l *Lexer) peekAt(n int) rune {
	if l.pos+n >= len(l.source) {
		return 0
	}
	return l.source[l.pos+n]
}
func (l *Lexer) advance() rune {
	ch := l.source[l.pos]
	l.pos++
	if ch == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return ch
}
func (l *Lexer) emit(tt TokenType, val string, line, col int) {
	l.tokens = append(l.tokens, Token{Type: tt, Value: val, Line: line, Col: col})
}
func (l *Lexer) skipWS() {
	for l.pos < len(l.source) && (l.peek() == ' ' || l.peek() == '\t' || l.peek() == '\r') {
		l.advance()
	}
}
func (l *Lexer) skipLineComment() {
	for l.pos < len(l.source) && l.peek() != '\n' {
		l.advance()
	}
}

func (l *Lexer) readStr() (string, error) {
	var sb strings.Builder
	l.advance() // opening quote
	for l.pos < len(l.source) {
		ch := l.peek()
		if ch == '"' {
			l.advance()
			return sb.String(), nil
		}
		if ch == '\\' {
			l.advance()
			esc := l.advance()
			switch esc {
			case 'n':
				sb.WriteRune('\n')
			case 't':
				sb.WriteRune('\t')
			case 'r':
				sb.WriteRune('\r')
			case '"':
				sb.WriteRune('"')
			case '\\':
				sb.WriteRune('\\')
			default:
				sb.WriteRune('\\')
				sb.WriteRune(esc)
			}
			continue
		}
		sb.WriteRune(l.advance())
	}
	return "", fmt.Errorf("unterminated string at line %d", l.line)
}

// f"Hello {name}, you have {count} messages"
// stored raw so parser/interpreter can handle interpolation
func (l *Lexer) readFString() (string, error) {
	var sb strings.Builder
	l.advance() // opening quote
	for l.pos < len(l.source) {
		ch := l.peek()
		if ch == '"' {
			l.advance()
			return sb.String(), nil
		}
		if ch == '\\' {
			l.advance()
			esc := l.advance()
			switch esc {
			case 'n':
				sb.WriteRune('\n')
			case 't':
				sb.WriteRune('\t')
			case '"':
				sb.WriteRune('"')
			case '\\':
				sb.WriteRune('\\')
			default:
				sb.WriteRune('\\')
				sb.WriteRune(esc)
			}
			continue
		}
		sb.WriteRune(l.advance())
	}
	return "", fmt.Errorf("unterminated f-string at line %d", l.line)
}

func (l *Lexer) readNum() string {
	var sb strings.Builder
	for l.pos < len(l.source) && (unicode.IsDigit(l.peek()) || l.peek() == '.') {
		sb.WriteRune(l.advance())
	}
	return sb.String()
}

func (l *Lexer) readIdent() string {
	var sb strings.Builder
	for l.pos < len(l.source) && (unicode.IsLetter(l.peek()) || unicode.IsDigit(l.peek()) || l.peek() == '_') {
		sb.WriteRune(l.advance())
	}
	return sb.String()
}

func (l *Lexer) Tokenize() ([]Token, error) {
	for l.pos < len(l.source) {
		l.skipWS()
		if l.pos >= len(l.source) {
			break
		}
		ln, col := l.line, l.col
		ch := l.peek()

		// Line comment ##
		if ch == '#' && l.peekAt(1) == '#' {
			l.skipLineComment()
			continue
		}

		// # runner<?command args {var}>  — glue language runner keyword
		if ch == '#' && isRunnerAhead(l) {
			cmd, err := l.readRunner()
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", ln, err)
			}
			l.emit(TOKEN_RUNNER, cmd, ln, col)
			continue
		}

		// #Import directive
		if ch == '#' {
			l.advance()
			ident := l.readIdent()
			if ident == "Import" {
				l.emit(TOKEN_IMPORT, "#Import", ln, col)
			} else {
				return nil, fmt.Errorf("unknown directive #%s at line %d", ident, ln)
			}
			continue
		}

		// Newline
		if ch == '\n' {
			l.advance()
			l.emit(TOKEN_NEWLINE, "\\n", ln, col)
			continue
		}

		// f-string
		if ch == 'f' && l.peekAt(1) == '"' {
			l.advance() // consume f
			s, err := l.readFString()
			if err != nil {
				return nil, err
			}
			l.emit(TOKEN_FSTRING, s, ln, col)
			continue
		}

		// String
		if ch == '"' {
			s, err := l.readStr()
			if err != nil {
				return nil, err
			}
			l.emit(TOKEN_STRING, s, ln, col)
			continue
		}

		// Number (including hex 0x...)
		if unicode.IsDigit(ch) || (ch == '0' && (l.peekAt(1) == 'x' || l.peekAt(1) == 'X')) {
			if ch == '0' && (l.peekAt(1) == 'x' || l.peekAt(1) == 'X') {
				var sb strings.Builder
				sb.WriteRune(l.advance())
				sb.WriteRune(l.advance()) // 0x
				for l.pos < len(l.source) && isHexDigit(l.peek()) {
					sb.WriteRune(l.advance())
				}
				l.emit(TOKEN_NUMBER, sb.String(), ln, col)
			} else {
				l.emit(TOKEN_NUMBER, l.readNum(), ln, col)
			}
			continue
		}

		// Identifier / keyword
		if unicode.IsLetter(ch) || ch == '_' {
			ident := l.readIdent()
			// Dotted builtins: open.window GUI.label GUI.on etc.
			if (ident == "open" || ident == "GUI") && l.pos < len(l.source) && l.peek() == '.' {
				l.advance() // consume '.'
				if l.pos < len(l.source) && (unicode.IsLetter(l.peek()) || l.peek() == '_') {
					method := l.readIdent()
					l.emit(TOKEN_IDENT, ident+"."+method, ln, col)
					continue
				}
			}
			if tt, ok := keywords[ident]; ok {
				l.emit(tt, ident, ln, col)
			} else {
				l.emit(TOKEN_IDENT, ident, ln, col)
			}
			continue
		}

		// Two/three-char operators
		n2 := l.peekAt(1)
		switch {
		case ch == '-' && n2 == '-' && l.peekAt(2) == '>':
			l.advance()
			l.advance()
			l.advance()
			l.emit(TOKEN_ARROW, "-->", ln, col)
			continue
		case ch == '=' && n2 == '>':
			l.advance()
			l.advance()
			l.emit(TOKEN_FATARROW, "=>", ln, col)
			continue
		case ch == '=' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_EQ, "==", ln, col)
			continue
		case ch == '!' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_NEQ, "!=", ln, col)
			continue
		case ch == '<' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_LTE, "<=", ln, col)
			continue
		case ch == '>' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_GTE, ">=", ln, col)
			continue
		case ch == '&' && n2 == '&':
			l.advance()
			l.advance()
			l.emit(TOKEN_AND, "&&", ln, col)
			continue
		case ch == '|' && n2 == '|':
			l.advance()
			l.advance()
			l.emit(TOKEN_OR, "||", ln, col)
			continue
		case ch == '+' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_PLUS_EQ, "+=", ln, col)
			continue
		case ch == '-' && n2 == '=':
			l.advance()
			l.advance()
			l.emit(TOKEN_MINUS_EQ, "-=", ln, col)
			continue
		}

		// Single-char
		l.advance()
		switch ch {
		case '=':
			l.emit(TOKEN_ASSIGN, "=", ln, col)
		case '+':
			l.emit(TOKEN_PLUS, "+", ln, col)
		case '-':
			l.emit(TOKEN_MINUS, "-", ln, col)
		case '*':
			l.emit(TOKEN_STAR, "*", ln, col)
		case '/':
			l.emit(TOKEN_SLASH, "/", ln, col)
		case '%':
			l.emit(TOKEN_PERCENT, "%", ln, col)
		case '<':
			l.emit(TOKEN_LT, "<", ln, col)
		case '>':
			l.emit(TOKEN_GT, ">", ln, col)
		case '!':
			l.emit(TOKEN_NOT, "!", ln, col)
		case '|':
			l.emit(TOKEN_PIPE, "|", ln, col)
		case '(':
			l.emit(TOKEN_LPAREN, "(", ln, col)
		case ')':
			l.emit(TOKEN_RPAREN, ")", ln, col)
		case '{':
			l.emit(TOKEN_LBRACE, "{", ln, col)
		case '}':
			l.emit(TOKEN_RBRACE, "}", ln, col)
		case '[':
			l.emit(TOKEN_LBRACKET, "[", ln, col)
		case ']':
			l.emit(TOKEN_RBRACKET, "]", ln, col)
		case ',':
			l.emit(TOKEN_COMMA, ",", ln, col)
		case ':':
			l.emit(TOKEN_COLON, ":", ln, col)
		case '.':
			l.emit(TOKEN_DOT, ".", ln, col)
		default:
			return nil, fmt.Errorf("unexpected char %q at line %d col %d", ch, ln, col)
		}
	}
	l.emit(TOKEN_EOF, "", l.line, l.col)
	return l.tokens, nil
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// isRunnerAhead checks if the current position starts "# runner<?"
func isRunnerAhead(l *Lexer) bool {
	// we're sitting on '#', need to see " runner<?" ahead
	// source from pos: #, space, r,u,n,n,e,r,<,?
	// peekAt(0) = '#' already confirmed by caller
	ahead := string(l.source[l.pos:])
	// trim leading # and whitespace
	rest := strings.TrimLeft(ahead[1:], " \t")
	return strings.HasPrefix(rest, "runner<?")
}

// readRunner consumes "# runner<? ... >" and returns the raw command string.
// Supports {varname} interpolation markers kept verbatim.
func (l *Lexer) readRunner() (string, error) {
	// consume '#'
	l.advance()
	// skip whitespace
	for l.pos < len(l.source) && (l.peek() == ' ' || l.peek() == '\t') {
		l.advance()
	}
	// consume "runner"
	for l.pos < len(l.source) && l.peek() != '<' {
		l.advance()
	}
	// consume '<'
	if l.pos >= len(l.source) {
		return "", fmt.Errorf("expected '<?' in runner directive")
	}
	l.advance()
	// consume '?'
	if l.pos >= len(l.source) || l.peek() != '?' {
		return "", fmt.Errorf("expected '?' after '<' in runner directive")
	}
	l.advance()

	// Strategy: find the LAST '>' on this line — that is the closing delimiter.
	// This correctly handles shell redirects like:
	//   # runner<?echo hello > /tmp/out.txt>
	// The final '>' after "out.txt" is the runner-close; everything before it
	// is the command, including any intermediate '>' redirect operators.
	lineEnd := l.pos
	for lineEnd < len(l.source) && l.source[lineEnd] != '\n' {
		lineEnd++
	}
	// Walk backwards to find last '>'
	closingIdx := -1
	for i := lineEnd - 1; i >= l.pos; i-- {
		if l.source[i] == '>' {
			closingIdx = i
			break
		}
	}
	if closingIdx < 0 {
		return "", fmt.Errorf("missing closing '>' in runner directive at line %d", l.line)
	}

	// Read from current position up to (not including) the closing '>'
	var sb strings.Builder
	for l.pos < closingIdx {
		sb.WriteRune(l.advance())
	}
	l.advance() // consume the closing '>'

	cmd := strings.TrimSpace(sb.String())
	if cmd == "" {
		return "", fmt.Errorf("empty runner command at line %d", l.line)
	}
	return cmd, nil
}
