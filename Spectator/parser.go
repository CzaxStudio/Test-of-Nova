package main

import (
	"fmt"
	"strconv"
	"strings"
)

type Parser struct {
	tokens []Token
	pos    int
}

func NewParser(tokens []Token) *Parser { return &Parser{tokens: tokens} }

func (p *Parser) peek() Token {
	for p.pos < len(p.tokens) && p.tokens[p.pos].Type == TOKEN_NEWLINE {
		p.pos++
	}
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.pos]
}
func (p *Parser) peekRaw() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.pos]
}
func (p *Parser) advance() Token {
	for p.pos < len(p.tokens) && p.tokens[p.pos].Type == TOKEN_NEWLINE {
		p.pos++
	}
	t := p.tokens[p.pos]
	p.pos++
	return t
}
func (p *Parser) expect(tt TokenType) (Token, error) {
	t := p.advance()
	if t.Type != tt {
		return t, fmt.Errorf("line %d: expected token %d, got %q (%d)", t.Line, tt, t.Value, t.Type)
	}
	return t, nil
}

func (p *Parser) Parse() (*Program, error) {
	prog := &Program{}
	for p.peek().Type != TOKEN_EOF {
		s, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if s != nil {
			prog.Statements = append(prog.Statements, s)
		}
	}
	return prog, nil
}

func (p *Parser) parseBlock() ([]Stmt, error) {
	if _, err := p.expect(TOKEN_LBRACE); err != nil {
		return nil, err
	}
	var stmts []Stmt
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		s, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if s != nil {
			stmts = append(stmts, s)
		}
	}
	if _, err := p.expect(TOKEN_RBRACE); err != nil {
		return nil, err
	}
	return stmts, nil
}

func (p *Parser) parseStmt() (Stmt, error) {
	t := p.peek()
	switch t.Type {
	case TOKEN_IMPORT:
		return p.parseImport()
	case TOKEN_DO:
		return p.parseDo()
	case TOKEN_TRACE, TOKEN_COMPUTE:
		return p.parseTrace()
	case TOKEN_LET:
		return p.parseAssign(true)
	case TOKEN_IF:
		return p.parseIf()
	case TOKEN_LOOP:
		return p.parseLoop()
	case TOKEN_EACH:
		return p.parseEach()
	case TOKEN_FUNC:
		return p.parseFunc()
	case TOKEN_RETURN:
		return p.parseReturn()
	case TOKEN_BREAK:
		p.advance()
		return &BreakStmt{Line: t.Line}, nil
	case TOKEN_CONTINUE:
		p.advance()
		return &ContinueStmt{Line: t.Line}, nil
	case TOKEN_TRY:
		return p.parseTry()
	case TOKEN_MATCH:
		return p.parseMatch()
	case TOKEN_SPAWN:
		return p.parseSpawn()
	case TOKEN_IDENT:
		return p.parseIdentStmt()
	case TOKEN_RUNNER:
		return p.parseRunner()
	}
	return nil, fmt.Errorf("line %d: unexpected token %q", t.Line, t.Value)
}

func (p *Parser) parseImport() (*ImportStmt, error) {
	t := p.advance()
	lib := p.advance()
	if lib.Type != TOKEN_IDENT && lib.Type != TOKEN_STRING {
		return nil, fmt.Errorf("line %d: expected library name after #Import", t.Line)
	}
	// Consume dotted suffixes: #Import Spec.GUI  →  library = "Spec.GUI"
	name := lib.Value
	for p.peekRaw().Type == TOKEN_DOT {
		p.pos++ // consume dot
		if p.peekRaw().Type == TOKEN_IDENT {
			next := p.tokens[p.pos]
			p.pos++
			name += "." + next.Value
		}
	}
	return &ImportStmt{Library: name, Line: t.Line}, nil
}

func (p *Parser) parseDo() (*DoStmt, error) {
	t := p.advance()
	arr := p.advance()
	if arr.Type != TOKEN_ARROW {
		return nil, fmt.Errorf("line %d: expected '-->' after 'do'", t.Line)
	}
	mod := p.advance()
	if mod.Type != TOKEN_IDENT {
		return nil, fmt.Errorf("line %d: expected module name", t.Line)
	}
	if _, err := p.expect(TOKEN_LPAREN); err != nil {
		return nil, err
	}
	args, err := p.parseArgList()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TOKEN_RPAREN); err != nil {
		return nil, err
	}
	// optional: capture = do --> Module(...)
	captureVar := ""
	// already handled at ident level; this is fine
	return &DoStmt{Module: mod.Value, Args: args, Capture: captureVar, Line: t.Line}, nil
}

func (p *Parser) parseTrace() (*TraceStmt, error) {
	t := p.advance()
	if _, err := p.expect(TOKEN_LPAREN); err != nil {
		return nil, err
	}
	args, err := p.parseArgList()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TOKEN_RPAREN); err != nil {
		return nil, err
	}
	return &TraceStmt{Args: args, Line: t.Line}, nil
}

func (p *Parser) parseAssign(isLet bool) (Stmt, error) {
	if isLet {
		p.advance()
	}
	name := p.advance()
	if name.Type != TOKEN_IDENT {
		return nil, fmt.Errorf("line %d: expected variable name", name.Line)
	}
	// map index assign: x["key"] = val
	if p.peek().Type == TOKEN_LBRACKET {
		p.advance()
		key, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_RBRACKET); err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_ASSIGN); err != nil {
			return nil, err
		}
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &MapAssignStmt{Map: name.Value, Key: key, Value: val, Line: name.Line}, nil
	}
	next := p.advance()
	if next.Type == TOKEN_ASSIGN {
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: val, IsLet: isLet, Line: name.Line}, nil
	}
	if next.Type == TOKEN_PLUS_EQ {
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: &BinaryExpr{Op: "+", Left: &Identifier{Name: name.Value, Line: name.Line}, Right: val}, IsLet: false, Line: name.Line}, nil
	}
	if next.Type == TOKEN_MINUS_EQ {
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: &BinaryExpr{Op: "-", Left: &Identifier{Name: name.Value, Line: name.Line}, Right: val}, IsLet: false, Line: name.Line}, nil
	}
	return nil, fmt.Errorf("line %d: expected = after variable name, got %q", name.Line, next.Value)
}

func (p *Parser) parseIdentStmt() (Stmt, error) {
	name := p.advance()
	next := p.peek()
	// map index assignment: name["key"] = val
	if next.Type == TOKEN_LBRACKET {
		p.advance()
		key, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_RBRACKET); err != nil {
			return nil, err
		}
		if p.peek().Type == TOKEN_ASSIGN {
			p.advance()
			val, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &MapAssignStmt{Map: name.Value, Key: key, Value: val, Line: name.Line}, nil
		}
	}
	// dot key assignment: m.key = val  →  MapAssignStmt with StringLit key
	if next.Type == TOKEN_DOT {
		p.advance() // consume dot
		key := p.advance()
		if key.Type != TOKEN_IDENT {
			return nil, fmt.Errorf("line %d: expected key name after '.'", name.Line)
		}
		if p.peek().Type == TOKEN_ASSIGN {
			p.advance()
			val, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			return &MapAssignStmt{Map: name.Value, Key: &StringLit{Value: key.Value}, Value: val, Line: name.Line}, nil
		}
		if p.peek().Type == TOKEN_PLUS_EQ {
			p.advance()
			val, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			old := &IndexExpr{List: &Identifier{Name: name.Value, Line: name.Line}, Index: &StringLit{Value: key.Value}}
			return &MapAssignStmt{Map: name.Value, Key: &StringLit{Value: key.Value}, Value: &BinaryExpr{Op: "+", Left: old, Right: val}, Line: name.Line}, nil
		}
		return nil, fmt.Errorf("line %d: expected = after %s.%s", name.Line, name.Value, key.Value)
	}
	if next.Type == TOKEN_ASSIGN {
		p.advance()
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: val, IsLet: false, Line: name.Line}, nil
	}
	if next.Type == TOKEN_PLUS_EQ {
		p.advance()
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: &BinaryExpr{Op: "+", Left: &Identifier{Name: name.Value, Line: name.Line}, Right: val}, IsLet: false, Line: name.Line}, nil
	}
	if next.Type == TOKEN_MINUS_EQ {
		p.advance()
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		return &AssignStmt{Name: name.Value, Value: &BinaryExpr{Op: "-", Left: &Identifier{Name: name.Value, Line: name.Line}, Right: val}, IsLet: false, Line: name.Line}, nil
	}
	if next.Type == TOKEN_LPAREN {
		p.advance()
		args, err := p.parseArgList()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_RPAREN); err != nil {
			return nil, err
		}
		return &ExprStmt{Expr: &CallExpr{Callee: name.Value, Args: args, Line: name.Line}, Line: name.Line}, nil
	}
	// GUI.html(...) / GUI.on(...) etc — dotted method call as statement
	if next.Type == TOKEN_DOT {
		p.advance() // consume dot
		method := p.peek()
		if method.Type == TOKEN_IDENT {
			p.advance() // consume method name
			if p.peek().Type == TOKEN_LPAREN {
				p.advance() // consume (
				args, err := p.parseArgList()
				if err != nil {
					return nil, err
				}
				if _, err := p.expect(TOKEN_RPAREN); err != nil {
					return nil, err
				}
				dottedName := name.Value + "." + method.Value
				return &ExprStmt{Expr: &CallExpr{Callee: dottedName, Args: args, Line: name.Line}, Line: name.Line}, nil
			}
		}
	}
	return nil, fmt.Errorf("line %d: unexpected identifier %q", name.Line, name.Value)
}

func (p *Parser) parseIf() (*IfStmt, error) {
	t := p.advance()
	cond, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	stmt := &IfStmt{Condition: cond, Body: body, Line: t.Line}
	// elseif chains
	for p.peek().Type == TOKEN_ELSEIF {
		p.advance()
		eicond, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		eibody, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		stmt.ElseIfs = append(stmt.ElseIfs, ElseIf{Condition: eicond, Body: eibody})
	}
	if p.peek().Type == TOKEN_ELSE {
		p.advance()
		elseBody, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		stmt.ElseBody = elseBody
	}
	return stmt, nil
}

func (p *Parser) parseLoop() (*LoopStmt, error) {
	t := p.advance()
	stmt := &LoopStmt{Line: t.Line}
	if p.peek().Type != TOKEN_LBRACE {
		count, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		stmt.Count = count
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	stmt.Body = body
	return stmt, nil
}

func (p *Parser) parseEach() (*EachStmt, error) {
	t := p.advance()
	varTok := p.advance()
	if varTok.Type != TOKEN_IDENT {
		return nil, fmt.Errorf("line %d: expected var name after 'each'", t.Line)
	}
	idxVar := ""
	// each item, idx : list  (optional index var)
	if p.peek().Type == TOKEN_COMMA {
		p.advance()
		idxTok := p.advance()
		if idxTok.Type != TOKEN_IDENT {
			return nil, fmt.Errorf("line %d: expected index var", t.Line)
		}
		idxVar = idxTok.Value
	}
	if _, err := p.expect(TOKEN_COLON); err != nil {
		return nil, err
	}
	list, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &EachStmt{Var: varTok.Value, IdxVar: idxVar, List: list, Body: body, Line: t.Line}, nil
}

func (p *Parser) parseFunc() (*FuncStmt, error) {
	t := p.advance()
	name := p.advance()
	if name.Type != TOKEN_IDENT {
		return nil, fmt.Errorf("line %d: expected function name", t.Line)
	}
	if _, err := p.expect(TOKEN_LPAREN); err != nil {
		return nil, err
	}
	var params []string
	for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
		param := p.advance()
		if param.Type != TOKEN_IDENT {
			return nil, fmt.Errorf("line %d: expected param name", param.Line)
		}
		params = append(params, param.Value)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	if _, err := p.expect(TOKEN_RPAREN); err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &FuncStmt{Name: name.Value, Params: params, Body: body, Line: t.Line}, nil
}

func (p *Parser) parseReturn() (*ReturnStmt, error) {
	t := p.advance()
	if p.peekRaw().Type == TOKEN_NEWLINE || p.peek().Type == TOKEN_RBRACE || p.peek().Type == TOKEN_EOF {
		return &ReturnStmt{Line: t.Line}, nil
	}
	val, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	return &ReturnStmt{Value: val, Line: t.Line}, nil
}

func (p *Parser) parseTry() (*TryStmt, error) {
	t := p.advance()
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TOKEN_CATCH); err != nil {
		return nil, err
	}
	errVar := "err"
	if p.peek().Type == TOKEN_IDENT {
		errVar = p.advance().Value
	}
	catchBody, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &TryStmt{Body: body, ErrVar: errVar, CatchBody: catchBody, Line: t.Line}, nil
}

func (p *Parser) parseMatch() (*MatchStmt, error) {
	t := p.advance()
	val, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TOKEN_LBRACE); err != nil {
		return nil, err
	}
	stmt := &MatchStmt{Value: val, Line: t.Line}
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		if p.peek().Type == TOKEN_WILDCARD {
			p.advance()
			if _, err := p.expect(TOKEN_FATARROW); err != nil {
				return nil, err
			}
			defaultBody, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			stmt.Default = defaultBody
			continue
		}
		pat, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_FATARROW); err != nil {
			return nil, err
		}
		caseBody, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		stmt.Cases = append(stmt.Cases, MatchCase{Pattern: pat, Body: caseBody})
	}
	if _, err := p.expect(TOKEN_RBRACE); err != nil {
		return nil, err
	}
	return stmt, nil
}

func (p *Parser) parseSpawn() (*SpawnStmt, error) {
	t := p.advance()
	call, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	return &SpawnStmt{Call: call, Line: t.Line}, nil
}

// ── Expression parsing ────────────────────────────────────────────────────────

func (p *Parser) parseArgList() ([]Expr, error) {
	var args []Expr
	for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
		arg, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	return args, nil
}

func (p *Parser) parseExpr() (Expr, error) { return p.parseConcat() }

func (p *Parser) parseConcat() (Expr, error) {
	left, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_ARROW {
		p.advance()
		right, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		left = &ConcatExpr{Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_OR {
		op := p.advance().Value
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseAnd() (Expr, error) {
	left, err := p.parseEquality()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_AND {
		op := p.advance().Value
		right, err := p.parseEquality()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseEquality() (Expr, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_EQ || p.peek().Type == TOKEN_NEQ {
		op := p.advance().Value
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseComparison() (Expr, error) {
	left, err := p.parseAddSub()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_LT || p.peek().Type == TOKEN_GT ||
		p.peek().Type == TOKEN_LTE || p.peek().Type == TOKEN_GTE {
		op := p.advance().Value
		right, err := p.parseAddSub()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseAddSub() (Expr, error) {
	left, err := p.parseMulDiv()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_PLUS || p.peek().Type == TOKEN_MINUS {
		op := p.advance().Value
		right, err := p.parseMulDiv()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseMulDiv() (Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOKEN_STAR || p.peek().Type == TOKEN_SLASH || p.peek().Type == TOKEN_PERCENT {
		op := p.advance().Value
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Op: op, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseUnary() (Expr, error) {
	if p.peek().Type == TOKEN_NOT {
		op := p.advance().Value
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Op: op, Operand: operand}, nil
	}
	if p.peek().Type == TOKEN_MINUS {
		op := p.advance().Value
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Op: op, Operand: operand}, nil
	}
	return p.parseIndex()
}

func (p *Parser) parseIndex() (Expr, error) {
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	// Chain both expr[key] and expr.key access
	for {
		if p.peek().Type == TOKEN_LBRACKET {
			p.advance()
			idx, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(TOKEN_RBRACKET); err != nil {
				return nil, err
			}
			expr = &IndexExpr{List: expr, Index: idx}
			continue
		}
		// Dot access: expr.key  →  expr["key"]
		// Only consume dot if next token after it is an IDENT (not a number/operator)
		if p.peek().Type == TOKEN_DOT {
			// peek ahead: is the token after the dot an identifier?
			saved := p.pos
			p.advance() // consume dot
			if p.peek().Type == TOKEN_IDENT {
				key := p.advance()
				// If followed by '(' it is a method call — leave for caller
				if p.peek().Type == TOKEN_LPAREN {
					p.pos = saved // backtrack
					break
				}
				// Otherwise treat as map key access: expr["key"]
				expr = &IndexExpr{List: expr, Index: &StringLit{Value: key.Value}}
				continue
			}
			p.pos = saved // backtrack if not ident
		}
		break
	}
	return expr, nil
}

func (p *Parser) parsePrimary() (Expr, error) {
	t := p.peek()
	switch t.Type {
	case TOKEN_STRING:
		p.advance()
		return &StringLit{Value: t.Value}, nil
	case TOKEN_FSTRING:
		p.advance()
		return parseFStringParts(t.Value), nil
	case TOKEN_NUMBER:
		p.advance()
		f, err := parseNumber(t.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q at line %d", t.Value, t.Line)
		}
		return &NumberLit{Value: f}, nil
	case TOKEN_BOOL:
		p.advance()
		return &BoolLit{Value: t.Value == "true"}, nil
	case TOKEN_NIL:
		p.advance()
		return &NilLit{}, nil
	case TOKEN_WILDCARD:
		p.advance()
		return &Identifier{Name: "_", Line: t.Line}, nil
	case TOKEN_CAPTURE:
		return p.parseCapture()
	case TOKEN_IDENT:
		p.advance()
		// Handle dotted calls: Module.method(...)
		// ONLY consume the dot here if followed by ident + '('
		// Plain dot access like m.key is handled by parseIndex after returning
		if p.peek().Type == TOKEN_DOT {
			saved := p.pos
			p.advance() // consume dot tentatively
			method := p.peek()
			if method.Type == TOKEN_IDENT {
				p.advance() // consume method name
				if p.peek().Type == TOKEN_LPAREN {
					// It's a dotted call: Module.method(...) — consume it here
					p.advance() // consume (
					args, err := p.parseArgList()
					if err != nil {
						return nil, err
					}
					if _, err := p.expect(TOKEN_RPAREN); err != nil {
						return nil, err
					}
					dottedName := t.Value + "." + method.Value
					return &CallExpr{Callee: dottedName, Args: args, Line: t.Line}, nil
				}
			}
			// Not a dotted call — backtrack and let parseIndex handle .key
			p.pos = saved
		}
		if p.peek().Type == TOKEN_LPAREN {
			p.advance()
			args, err := p.parseArgList()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(TOKEN_RPAREN); err != nil {
				return nil, err
			}
			return &CallExpr{Callee: t.Value, Args: args, Line: t.Line}, nil
		}
		return &Identifier{Name: t.Value, Line: t.Line}, nil
	case TOKEN_LPAREN:
		p.advance()
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_RPAREN); err != nil {
			return nil, err
		}
		return expr, nil
	case TOKEN_LBRACKET:
		return p.parseListLit()
	case TOKEN_LBRACE:
		return p.parseMapLit()
	case TOKEN_RUNNER:
		return p.parseRunnerExpr()
	case TOKEN_FUNC:
		// Inline anonymous function: func(params) { body }
		p.advance() // consume func
		if _, err := p.expect(TOKEN_LPAREN); err != nil {
			return nil, err
		}
		var params []string
		for p.peek().Type != TOKEN_RPAREN && p.peek().Type != TOKEN_EOF {
			param, err := p.expect(TOKEN_IDENT)
			if err != nil {
				return nil, err
			}
			params = append(params, param.Value)
			if p.peek().Type == TOKEN_COMMA {
				p.advance()
			}
		}
		if _, err := p.expect(TOKEN_RPAREN); err != nil {
			return nil, err
		}
		body, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		// Return a special inline func literal — we reuse FuncStmt info via a wrapper
		return &InlineFuncExpr{Params: params, Body: body, Line: t.Line}, nil
	}
	return nil, fmt.Errorf("line %d: unexpected token %q in expression", t.Line, t.Value)
}

func (p *Parser) parseCapture() (*CaptureExpr, error) {
	t := p.advance()
	if _, err := p.expect(TOKEN_LPAREN); err != nil {
		return nil, err
	}
	var prompt Expr
	if p.peek().Type != TOKEN_RPAREN {
		var err error
		prompt, err = p.parseExpr()
		if err != nil {
			return nil, err
		}
	} else {
		prompt = &StringLit{Value: ""}
	}
	if _, err := p.expect(TOKEN_RPAREN); err != nil {
		return nil, err
	}
	return &CaptureExpr{Prompt: prompt, Line: t.Line}, nil
}

func (p *Parser) parseListLit() (*ListLit, error) {
	p.advance()
	var elems []Expr
	for p.peek().Type != TOKEN_RBRACKET && p.peek().Type != TOKEN_EOF {
		e, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		elems = append(elems, e)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	if _, err := p.expect(TOKEN_RBRACKET); err != nil {
		return nil, err
	}
	return &ListLit{Elements: elems}, nil
}

func (p *Parser) parseMapLit() (*MapLit, error) {
	p.advance() // {
	m := &MapLit{}
	for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
		key, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_COLON); err != nil {
			return nil, err
		}
		val, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		m.Keys = append(m.Keys, key)
		m.Values = append(m.Values, val)
		if p.peek().Type == TOKEN_COMMA {
			p.advance()
		}
	}
	if _, err := p.expect(TOKEN_RBRACE); err != nil {
		return nil, err
	}
	return m, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseNumber(s string) (float64, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseInt(s[2:], 16, 64)
		return float64(n), err
	}
	return strconv.ParseFloat(s, 64)
}

// parseFStringParts breaks f"Hello {name}!" into parts
func parseFStringParts(raw string) *InterpolatedString {
	var parts []Expr
	i := 0
	var sb strings.Builder
	for i < len(raw) {
		if raw[i] == '{' {
			if sb.Len() > 0 {
				parts = append(parts, &StringLit{Value: sb.String()})
				sb.Reset()
			}
			i++
			var expr strings.Builder
			depth := 1
			for i < len(raw) && depth > 0 {
				if raw[i] == '{' {
					depth++
				} else if raw[i] == '}' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				expr.WriteByte(raw[i])
				i++
			}
			exprStr := strings.TrimSpace(expr.String())
			if exprStr != "" {
				parts = append(parts, &Identifier{Name: exprStr})
			}
		} else {
			sb.WriteByte(raw[i])
			i++
		}
	}
	if sb.Len() > 0 {
		parts = append(parts, &StringLit{Value: sb.String()})
	}
	return &InterpolatedString{Parts: parts}
}

// ── Runner parsing ─────────────────────────────────────────────────────────────

// parseRunner handles:
//
//	# runner<?cmd>                  → live passthrough
//	# runner<?cmd> | # runner<?cmd2> → pipe chain
//	# runner<?cmd> {                 → with stdin body
//	    "input line"
//	    varname
//	}
func (p *Parser) parseRunner() (Stmt, error) {
	t := p.advance() // consume TOKEN_RUNNER (value = raw command)
	stmt := &RunnerStmt{RawCmd: t.Value, Mode: "live", Line: t.Line}

	// Check for pipe: # runner<?a> | # runner<?b>
	if p.peek().Type == TOKEN_PIPE {
		p.advance()
		next, err := p.parseRunner()
		if err != nil {
			return nil, err
		}
		if nr, ok := next.(*RunnerStmt); ok {
			stmt.PipeTo = nr
		}
	}

	// Check for stdin body block: # runner<?cmd> { ... }
	if p.peek().Type == TOKEN_LBRACE {
		p.advance() // consume {
		for p.peek().Type != TOKEN_RBRACE && p.peek().Type != TOKEN_EOF {
			expr, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			stmt.Stdin = append(stmt.Stdin, expr)
		}
		if _, err := p.expect(TOKEN_RBRACE); err != nil {
			return nil, err
		}
	}

	return stmt, nil
}

// parseRunnerExpr handles # runner<?cmd> appearing as an expression (RHS of assignment)
func (p *Parser) parseRunnerExpr() (*RunnerExpr, error) {
	t := p.advance() // consume TOKEN_RUNNER
	expr := &RunnerExpr{RawCmd: t.Value, Line: t.Line}

	// pipe chaining as expression
	if p.peek().Type == TOKEN_PIPE {
		p.advance()
		next, err := p.parseRunnerExpr()
		if err != nil {
			return nil, err
		}
		expr.PipeTo = next
	}
	return expr, nil
}
