package main

type Node interface{ nodeType() string }
type Stmt interface {
	Node
	stmtNode()
}
type Expr interface {
	Node
	exprNode()
}

type Program struct{ Statements []Stmt }

func (p *Program) nodeType() string { return "Program" }

type AssignStmt struct {
	Name  string
	Value Expr
	IsLet bool
	Line  int
}

func (a *AssignStmt) nodeType() string { return "AssignStmt" }
func (a *AssignStmt) stmtNode()        {}

type TraceStmt struct {
	Args []Expr
	Line int
}

func (t *TraceStmt) nodeType() string { return "TraceStmt" }
func (t *TraceStmt) stmtNode()        {}

type DoStmt struct {
	Module  string
	Args    []Expr
	Capture string
	Line    int
}

func (d *DoStmt) nodeType() string { return "DoStmt" }
func (d *DoStmt) stmtNode()        {}

type ImportStmt struct {
	Library string
	Line    int
}

func (i *ImportStmt) nodeType() string { return "ImportStmt" }
func (i *ImportStmt) stmtNode()        {}

type IfStmt struct {
	Condition Expr
	Body      []Stmt
	ElseIfs   []ElseIf
	ElseBody  []Stmt
	Line      int
}
type ElseIf struct {
	Condition Expr
	Body      []Stmt
}

func (i *IfStmt) nodeType() string { return "IfStmt" }
func (i *IfStmt) stmtNode()        {}

type LoopStmt struct {
	Count Expr
	Body  []Stmt
	Line  int
}

func (l *LoopStmt) nodeType() string { return "LoopStmt" }
func (l *LoopStmt) stmtNode()        {}

type EachStmt struct {
	Var    string
	IdxVar string
	List   Expr
	Body   []Stmt
	Line   int
}

func (e *EachStmt) nodeType() string { return "EachStmt" }
func (e *EachStmt) stmtNode()        {}

type FuncStmt struct {
	Name   string
	Params []string
	Body   []Stmt
	Line   int
}

func (f *FuncStmt) nodeType() string { return "FuncStmt" }
func (f *FuncStmt) stmtNode()        {}

type ReturnStmt struct {
	Value Expr
	Line  int
}

func (r *ReturnStmt) nodeType() string { return "ReturnStmt" }
func (r *ReturnStmt) stmtNode()        {}

type BreakStmt struct{ Line int }

func (b *BreakStmt) nodeType() string { return "BreakStmt" }
func (b *BreakStmt) stmtNode()        {}

type ContinueStmt struct{ Line int }

func (c *ContinueStmt) nodeType() string { return "ContinueStmt" }
func (c *ContinueStmt) stmtNode()        {}

type ExprStmt struct {
	Expr Expr
	Line int
}

func (e *ExprStmt) nodeType() string { return "ExprStmt" }
func (e *ExprStmt) stmtNode()        {}

// try { } catch err { }
type TryStmt struct {
	Body      []Stmt
	ErrVar    string
	CatchBody []Stmt
	Line      int
}

func (t *TryStmt) nodeType() string { return "TryStmt" }
func (t *TryStmt) stmtNode()        {}

// match val { "a" => { } _ => { } }
type MatchStmt struct {
	Value   Expr
	Cases   []MatchCase
	Default []Stmt
	Line    int
}
type MatchCase struct {
	Pattern Expr
	Body    []Stmt
}

func (m *MatchStmt) nodeType() string { return "MatchStmt" }
func (m *MatchStmt) stmtNode()        {}

// spawn func() { }   or   spawn funcName(args)
type SpawnStmt struct {
	Call Expr
	Line int
}

func (s *SpawnStmt) nodeType() string { return "SpawnStmt" }
func (s *SpawnStmt) stmtNode()        {}

// map assignment: x["key"] = val
type MapAssignStmt struct {
	Map   string
	Key   Expr
	Value Expr
	Line  int
}

func (m *MapAssignStmt) nodeType() string { return "MapAssignStmt" }
func (m *MapAssignStmt) stmtNode()        {}

// ── Expressions ───────────────────────────────────────────────────────────────

type StringLit struct{ Value string }

func (s *StringLit) nodeType() string { return "StringLit" }
func (s *StringLit) exprNode()        {}

type NumberLit struct{ Value float64 }

func (n *NumberLit) nodeType() string { return "NumberLit" }
func (n *NumberLit) exprNode()        {}

type BoolLit struct{ Value bool }

func (b *BoolLit) nodeType() string { return "BoolLit" }
func (b *BoolLit) exprNode()        {}

type NilLit struct{}

func (n *NilLit) nodeType() string { return "NilLit" }
func (n *NilLit) exprNode()        {}

type Identifier struct {
	Name string
	Line int
}

func (i *Identifier) nodeType() string { return "Identifier" }
func (i *Identifier) exprNode()        {}

type ConcatExpr struct {
	Left  Expr
	Right Expr
}

func (c *ConcatExpr) nodeType() string { return "ConcatExpr" }
func (c *ConcatExpr) exprNode()        {}

type BinaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
}

func (b *BinaryExpr) nodeType() string { return "BinaryExpr" }
func (b *BinaryExpr) exprNode()        {}

type UnaryExpr struct {
	Op      string
	Operand Expr
}

func (u *UnaryExpr) nodeType() string { return "UnaryExpr" }
func (u *UnaryExpr) exprNode()        {}

type CaptureExpr struct {
	Prompt Expr
	Line   int
}

func (c *CaptureExpr) nodeType() string { return "CaptureExpr" }
func (c *CaptureExpr) exprNode()        {}

type CallExpr struct {
	Callee string
	Args   []Expr
	Line   int
}

func (c *CallExpr) nodeType() string { return "CallExpr" }
func (c *CallExpr) exprNode()        {}

type ListLit struct{ Elements []Expr }

func (l *ListLit) nodeType() string { return "ListLit" }
func (l *ListLit) exprNode()        {}

type MapLit struct {
	Keys   []Expr
	Values []Expr
}

func (m *MapLit) nodeType() string { return "MapLit" }
func (m *MapLit) exprNode()        {}

type IndexExpr struct {
	List  Expr
	Index Expr
}

func (i *IndexExpr) nodeType() string { return "IndexExpr" }
func (i *IndexExpr) exprNode()        {}

// Interpolated string: f"Hello {name}!"
type InterpolatedString struct{ Parts []Expr }

func (i *InterpolatedString) nodeType() string { return "InterpolatedString" }
func (i *InterpolatedString) exprNode()        {}

// ── Runner nodes ───────────────────────────────────────────────────────────────

// RunnerStmt: # runner<?cmd {var} args>
// RawCmd  = raw command template e.g. "nmap -sV {target}"
// CaptureVar = if non-empty, stdout is captured into this variable
// Stdin   = optional lines to feed into the process stdin
// PipeTo  = optional chained runner (output of this feeds stdin of next)
// Mode    = "live" (passthrough) | "capture" (return string) | "silent"
type RunnerStmt struct {
	RawCmd     string      // raw command template with {var} placeholders
	CaptureVar string      // variable name to store output in (empty = live print)
	Stdin      []Expr      // expressions whose string values are piped to stdin
	PipeTo     *RunnerStmt // chained runner (pipe operator)
	Mode       string      // "live" | "capture" | "silent"
	Line       int
}

func (r *RunnerStmt) nodeType() string { return "RunnerStmt" }
func (r *RunnerStmt) stmtNode()        {}

// RunnerExpr: used when # runner<?...> appears on the right-hand side of an assignment
type RunnerExpr struct {
	RawCmd string
	PipeTo *RunnerExpr
	Line   int
}

func (r *RunnerExpr) nodeType() string { return "RunnerExpr" }
func (r *RunnerExpr) exprNode()        {}

// InlineFuncExpr: anonymous function used as an expression value
// e.g. GUI.on(app, "event", func(data) { ... })
type InlineFuncExpr struct {
	Params []string
	Body   []Stmt
	Line   int
}

func (f *InlineFuncExpr) nodeType() string { return "InlineFuncExpr" }
func (f *InlineFuncExpr) exprNode()        {}
