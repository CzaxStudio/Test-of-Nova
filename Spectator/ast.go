// AST node types for Spectator.
// via interfaces with a nodeType() marker method.

type Node interface{ nodeType() string }
type Stmt interface {
	Node
	stmtNode()
}
type Expr interface {
	Node
	exprNode()
}

// statements

type Program struct{ Body []Stmt }

type AssignStmt struct {
	Name  string
	Value Expr
	IsLet bool
	Line  int
}

type MapAssignStmt struct {
	Map   string
	Key   Expr
	Value Expr
	Line  int
}

type DoStmt struct {
	Call Expr
	Line int
}

type ImportStmt struct {
	Library string
	Line    int
}

type IfStmt struct {
	Condition Expr
	Then      []Stmt
	ElseIfs   []ElseIf
	Else      []Stmt
	Line      int
}

type ElseIf struct {
	Condition Expr
	Body      []Stmt
}

type LoopStmt struct {
	Count Expr // nil = infinite
	Body  []Stmt
	Line  int
}

type EachStmt struct {
	Value    string
	Key      string // optional
	Iterable Expr
	Body     []Stmt
	Line     int
}

type MatchStmt struct {
	Subject Expr
	Cases   []MatchCase
	Line    int
}

type MatchCase struct {
	Pattern Expr // nil = wildcard (_)
	Body    []Stmt
}

type FuncStmt struct {
	Name   string
	Params []string
	Body   []Stmt
	Line   int
}

type ReturnStmt struct {
	Value Expr
	Line  int
}

type BreakStmt struct{ Line int }

type ThrowStmt struct {
	Message Expr
	Line    int
}

type TryCatchStmt struct {
	Try     []Stmt
	ErrVar  string
	Catch   []Stmt
	Line    int
}

type SpawnStmt struct {
	Call Expr
	Line int
}

type RunnerStmt struct {
	Command string
	Pipe    string
	Line    int
}

type ExprStmt struct {
	Expr Expr
	Line int
}

// expressions

type NumberLit struct {
	Value float64
	Line  int
}

type StringLit struct {
	Value string
	Line  int
}

type BoolLit struct {
	Value bool
	Line  int
}

type NilLit struct{ Line int }

type Identifier struct {
	Name string
	Line int
}

type BinaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
	Line  int
}

type UnaryExpr struct {
	Op      string
	Operand Expr
	Line    int
}

type CallExpr struct {
	Callee string
	Args   []Expr
	Line   int
}

type IndexExpr struct {
	List  Expr
	Index Expr
	Line  int
}

type ListLit struct {
	Elements []Expr
	Line     int
}

type MapLit struct {
	Keys   []Expr
	Values []Expr
	Line   int
}

type FStringExpr struct {
	Parts []FStringPart
	Line  int
}

type FStringPart struct {
	IsExpr bool
	Text   string
	Expr   Expr
}

type ConcatExpr struct {
	Left  Expr
	Right Expr
	Line  int
}

type RunnerExpr struct {
	Command string
	Pipe    string
	Line    int
}

type InlineFuncExpr struct {
	Params []string
	Body   []Stmt
	Line   int
}

// nodeType / stmtNode / exprNode markers

func (n *Program) nodeType() string        { return "Program" }
func (n *AssignStmt) nodeType() string     { return "AssignStmt" }
func (n *MapAssignStmt) nodeType() string  { return "MapAssignStmt" }
func (n *DoStmt) nodeType() string         { return "DoStmt" }
func (n *ImportStmt) nodeType() string     { return "ImportStmt" }
func (n *IfStmt) nodeType() string         { return "IfStmt" }
func (n *LoopStmt) nodeType() string       { return "LoopStmt" }
func (n *EachStmt) nodeType() string       { return "EachStmt" }
func (n *MatchStmt) nodeType() string      { return "MatchStmt" }
func (n *FuncStmt) nodeType() string       { return "FuncStmt" }
func (n *ReturnStmt) nodeType() string     { return "ReturnStmt" }
func (n *BreakStmt) nodeType() string      { return "BreakStmt" }
func (n *ThrowStmt) nodeType() string      { return "ThrowStmt" }
func (n *TryCatchStmt) nodeType() string   { return "TryCatchStmt" }
func (n *SpawnStmt) nodeType() string      { return "SpawnStmt" }
func (n *RunnerStmt) nodeType() string     { return "RunnerStmt" }
func (n *ExprStmt) nodeType() string       { return "ExprStmt" }
func (n *NumberLit) nodeType() string      { return "NumberLit" }
func (n *StringLit) nodeType() string      { return "StringLit" }
func (n *BoolLit) nodeType() string        { return "BoolLit" }
func (n *NilLit) nodeType() string         { return "NilLit" }
func (n *Identifier) nodeType() string     { return "Identifier" }
func (n *BinaryExpr) nodeType() string     { return "BinaryExpr" }
func (n *UnaryExpr) nodeType() string      { return "UnaryExpr" }
func (n *CallExpr) nodeType() string       { return "CallExpr" }
func (n *IndexExpr) nodeType() string      { return "IndexExpr" }
func (n *ListLit) nodeType() string        { return "ListLit" }
func (n *MapLit) nodeType() string         { return "MapLit" }
func (n *FStringExpr) nodeType() string    { return "FStringExpr" }
func (n *ConcatExpr) nodeType() string     { return "ConcatExpr" }
func (n *RunnerExpr) nodeType() string     { return "RunnerExpr" }
func (n *InlineFuncExpr) nodeType() string { return "InlineFuncExpr" }

func (n *AssignStmt) stmtNode()    {}
func (n *MapAssignStmt) stmtNode() {}
func (n *DoStmt) stmtNode()        {}
func (n *ImportStmt) stmtNode()    {}
func (n *IfStmt) stmtNode()        {}
func (n *LoopStmt) stmtNode()      {}
func (n *EachStmt) stmtNode()      {}
func (n *MatchStmt) stmtNode()     {}
func (n *FuncStmt) stmtNode()      {}
func (n *ReturnStmt) stmtNode()    {}
func (n *BreakStmt) stmtNode()     {}
func (n *ThrowStmt) stmtNode()     {}
func (n *TryCatchStmt) stmtNode()  {}
func (n *SpawnStmt) stmtNode()     {}
func (n *RunnerStmt) stmtNode()    {}
func (n *ExprStmt) stmtNode()      {}

func (n *NumberLit) exprNode()      {}
func (n *StringLit) exprNode()      {}
func (n *BoolLit) exprNode()        {}
func (n *NilLit) exprNode()         {}
func (n *Identifier) exprNode()     {}
func (n *BinaryExpr) exprNode()     {}
func (n *UnaryExpr) exprNode()      {}
func (n *CallExpr) exprNode()       {}
func (n *IndexExpr) exprNode()      {}
func (n *ListLit) exprNode()        {}
func (n *MapLit) exprNode()         {}
func (n *FStringExpr) exprNode()    {}
func (n *ConcatExpr) exprNode()     {}
func (n *RunnerExpr) exprNode()     {}
func (n *InlineFuncExpr) exprNode() {}

// stmtLine returns the line number of a statement, used in error messages
func stmtLine(s Stmt) int {
	switch v := s.(type) {
	case *AssignStmt:    return v.Line
	case *MapAssignStmt: return v.Line
	case *DoStmt:        return v.Line
	case *ImportStmt:    return v.Line
	case *IfStmt:        return v.Line
	case *LoopStmt:      return v.Line
	case *EachStmt:      return v.Line
	case *MatchStmt:     return v.Line
	case *FuncStmt:      return v.Line
	case *ReturnStmt:    return v.Line
	case *BreakStmt:     return v.Line
	case *ThrowStmt:     return v.Line
	case *TryCatchStmt:  return v.Line
	case *SpawnStmt:     return v.Line
	case *RunnerStmt:    return v.Line
	case *ExprStmt:      return v.Line
	}
	return 0
}
