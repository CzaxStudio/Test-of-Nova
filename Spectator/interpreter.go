package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Signals ───────────────────────────────────────────────────────────────────

type ReturnSignal struct{ Value interface{} }
type BreakSignal struct{}
type ContinueSignal struct{}
type SpectatorError struct{ Message string }

func (r ReturnSignal) Error() string    { return "return" }
func (b BreakSignal) Error() string     { return "break" }
func (c ContinueSignal) Error() string  { return "continue" }
func (e *SpectatorError) Error() string { return e.Message }

// ── Env ───────────────────────────────────────────────────────────────────────

type Env struct {
	vars   map[string]interface{}
	parent *Env
	mu     sync.RWMutex
}

func NewEnv(parent *Env) *Env { return &Env{vars: make(map[string]interface{}), parent: parent} }

func (e *Env) Get(name string) (interface{}, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if v, ok := e.vars[name]; ok {
		return v, true
	}
	if e.parent != nil {
		return e.parent.Get(name)
	}
	return nil, false
}
func (e *Env) Set(name string, val interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vars[name] = val
}
func (e *Env) SetExisting(name string, val interface{}) bool {
	e.mu.Lock()
	if _, ok := e.vars[name]; ok {
		e.vars[name] = val
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()
	if e.parent != nil {
		return e.parent.SetExisting(name, val)
	}
	return false
}

type UserFunc struct {
	Params []string
	Body   []Stmt
	Env    *Env
}

// ── Interpreter ───────────────────────────────────────────────────────────────

type Interpreter struct {
	global      *Env
	reader      *bufio.Reader
	libs        map[string]bool
	currentLine int // line number of statement currently executing
}

func NewInterpreter() *Interpreter {
	interp := &Interpreter{global: NewEnv(nil), reader: bufio.NewReader(os.Stdin), libs: make(map[string]bool)}
	return interp
}

func (interp *Interpreter) Run(prog *Program) error {
	for _, stmt := range prog.Statements {
		interp.currentLine = stmtLine(stmt)
		if err := interp.execStmt(stmt, interp.global); err != nil {
			if _, ok := err.(ReturnSignal); ok {
				return nil
			}
			return annotateErr(err, interp.currentLine)
		}
	}
	return nil
}

// stmtLine extracts the source line number from any Stmt node.
func stmtLine(s Stmt) int {
	switch v := s.(type) {
	case *AssignStmt:
		return v.Line
	case *MapAssignStmt:
		return v.Line
	case *TraceStmt:
		return v.Line
	case *DoStmt:
		return v.Line
	case *ImportStmt:
		return v.Line
	case *IfStmt:
		return v.Line
	case *LoopStmt:
		return v.Line
	case *EachStmt:
		return v.Line
	case *FuncStmt:
		return v.Line
	case *ReturnStmt:
		return v.Line
	case *BreakStmt:
		return v.Line
	case *ContinueStmt:
		return v.Line
	case *ExprStmt:
		return v.Line
	case *TryStmt:
		return v.Line
	case *MatchStmt:
		return v.Line
	case *SpawnStmt:
		return v.Line
	case *RunnerStmt:
		return v.Line
	}
	return 0
}

// annotateErr prepends "line N: " to an error if it doesn't already have one.
func annotateErr(err error, line int) error {
	if err == nil || line == 0 {
		return err
	}
	// Don't annotate signals — they are control flow, not errors
	switch err.(type) {
	case ReturnSignal, BreakSignal, ContinueSignal:
		return err
	}
	msg := err.Error()
	if len(msg) > 5 && msg[:5] == "line " {
		return err
	} // already annotated
	return fmt.Errorf("line %d: %s", line, msg)
}

// ── Statements ────────────────────────────────────────────────────────────────

func (interp *Interpreter) execStmt(stmt Stmt, env *Env) error {
	switch s := stmt.(type) {

	case *ImportStmt:
		return interp.execImport(s)

	case *AssignStmt:
		val, err := interp.evalExpr(s.Value, env)
		if err != nil {
			return err
		}
		if !s.IsLet && env.SetExisting(s.Name, val) {
			return nil
		}
		env.Set(s.Name, val)
		return nil

	case *MapAssignStmt:
		mapVal, ok := env.Get(s.Map)
		if !ok {
			return fmt.Errorf("line %d: undefined variable %q", s.Line, s.Map)
		}
		key, err := interp.evalExpr(s.Key, env)
		if err != nil {
			return err
		}
		val, err := interp.evalExpr(s.Value, env)
		if err != nil {
			return err
		}
		switch m := mapVal.(type) {
		case map[string]interface{}:
			m[toStr(key)] = val
		case []interface{}:
			idx := int(toFloat(key))
			if idx < 0 || idx >= len(m) {
				return fmt.Errorf("index %d out of range", idx)
			}
			m[idx] = val
		default:
			return fmt.Errorf("line %d: %q is not indexable", s.Line, s.Map)
		}
		return nil

	case *TraceStmt:
		var parts []string
		for _, arg := range s.Args {
			v, err := interp.evalExpr(arg, env)
			if err != nil {
				return err
			}
			parts = append(parts, toStr(v))
		}
		fmt.Println(strings.Join(parts, ""))
		return nil

	case *DoStmt:
		args := make([]interface{}, len(s.Args))
		for i, a := range s.Args {
			v, err := interp.evalExpr(a, env)
			if err != nil {
				return err
			}
			args[i] = v
		}
		result, err := interp.callModule(s.Module, args)
		if err != nil {
			return fmt.Errorf("module %s: %w", s.Module, err)
		}
		if result != nil {
			fmt.Println(result)
		}
		return nil

	case *IfStmt:
		cond, err := interp.evalExpr(s.Condition, env)
		if err != nil {
			return err
		}
		if isTruthy(cond) {
			return interp.execBlock(s.Body, NewEnv(env))
		}
		for _, ei := range s.ElseIfs {
			ec, err := interp.evalExpr(ei.Condition, env)
			if err != nil {
				return err
			}
			if isTruthy(ec) {
				return interp.execBlock(ei.Body, NewEnv(env))
			}
		}
		if len(s.ElseBody) > 0 {
			return interp.execBlock(s.ElseBody, NewEnv(env))
		}
		return nil

	case *LoopStmt:
		if s.Count != nil {
			cv, err := interp.evalExpr(s.Count, env)
			if err != nil {
				return err
			}
			n := int(toFloat(cv))
			for i := 0; i < n; i++ {
				child := NewEnv(env)
				child.Set("_i", float64(i))
				if err := interp.execBlock(s.Body, child); err != nil {
					if _, ok := err.(BreakSignal); ok {
						break
					}
					if _, ok := err.(ContinueSignal); ok {
						continue
					}
					return err
				}
			}
		} else {
			for {
				child := NewEnv(env)
				if err := interp.execBlock(s.Body, child); err != nil {
					if _, ok := err.(BreakSignal); ok {
						break
					}
					if _, ok := err.(ContinueSignal); ok {
						continue
					}
					return err
				}
			}
		}
		return nil

	case *EachStmt:
		listVal, err := interp.evalExpr(s.List, env)
		if err != nil {
			return err
		}
		switch lv := listVal.(type) {
		case []interface{}:
			for idx, item := range lv {
				child := NewEnv(env)
				child.Set(s.Var, item)
				if s.IdxVar != "" {
					child.Set(s.IdxVar, float64(idx))
				}
				if err := interp.execBlock(s.Body, child); err != nil {
					if _, ok := err.(BreakSignal); ok {
						break
					}
					if _, ok := err.(ContinueSignal); ok {
						continue
					}
					return err
				}
			}
		case map[string]interface{}:
			for k, v := range lv {
				child := NewEnv(env)
				child.Set(s.Var, k)
				if s.IdxVar != "" {
					child.Set(s.IdxVar, v)
				}
				if err := interp.execBlock(s.Body, child); err != nil {
					if _, ok := err.(BreakSignal); ok {
						break
					}
					if _, ok := err.(ContinueSignal); ok {
						continue
					}
					return err
				}
			}
		default:
			items := []interface{}{listVal}
			for _, item := range items {
				child := NewEnv(env)
				child.Set(s.Var, item)
				if err := interp.execBlock(s.Body, child); err != nil {
					if _, ok := err.(BreakSignal); ok {
						break
					}
					return err
				}
			}
		}
		return nil

	case *FuncStmt:
		env.Set(s.Name, &UserFunc{Params: s.Params, Body: s.Body, Env: env})
		return nil

	case *ReturnStmt:
		var val interface{}
		if s.Value != nil {
			var err error
			val, err = interp.evalExpr(s.Value, env)
			if err != nil {
				return err
			}
		}
		return ReturnSignal{Value: val}

	case *BreakStmt:
		return BreakSignal{}
	case *ContinueStmt:
		return ContinueSignal{}

	case *TryStmt:
		err := interp.execBlock(s.Body, NewEnv(env))
		if err != nil {
			if _, ok := err.(ReturnSignal); ok {
				return err
			}
			if _, ok := err.(BreakSignal); ok {
				return err
			}
			child := NewEnv(env)
			child.Set(s.ErrVar, err.Error())
			return interp.execBlock(s.CatchBody, child)
		}
		return nil

	case *MatchStmt:
		val, err := interp.evalExpr(s.Value, env)
		if err != nil {
			return err
		}
		for _, mc := range s.Cases {
			pat, err := interp.evalExpr(mc.Pattern, env)
			if err != nil {
				return err
			}
			if toStr(val) == toStr(pat) || val == pat {
				return interp.execBlock(mc.Body, NewEnv(env))
			}
		}
		if len(s.Default) > 0 {
			return interp.execBlock(s.Default, NewEnv(env))
		}
		return nil

	case *SpawnStmt:
		go func() {
			interp.evalExpr(s.Call, env) //nolint:errcheck
		}()
		return nil

	case *ExprStmt:
		_, err := interp.evalExpr(s.Expr, env)
		return err

	case *RunnerStmt:
		// Handle assignment: if CaptureVar is set by the parser wrapper, use capture mode
		return interp.execRunner(s, env)
	}
	return fmt.Errorf("unknown statement: %T", stmt)
}

func (interp *Interpreter) execBlock(stmts []Stmt, env *Env) error {
	for _, s := range stmts {
		interp.currentLine = stmtLine(s)
		if err := interp.execStmt(s, env); err != nil {
			return annotateErr(err, interp.currentLine)
		}
	}
	return nil
}

// ── Expressions ───────────────────────────────────────────────────────────────

func (interp *Interpreter) evalExpr(expr Expr, env *Env) (interface{}, error) {
	switch e := expr.(type) {
	case *StringLit:
		return e.Value, nil
	case *NumberLit:
		return e.Value, nil
	case *BoolLit:
		return e.Value, nil
	case *NilLit:
		return nil, nil
	case *Identifier:
		if e.Name == "_" {
			return nil, nil
		}
		if v, ok := env.Get(e.Name); ok {
			return v, nil
		}
		return nil, fmt.Errorf("line %d: undefined variable %q", e.Line, e.Name)
	case *InterpolatedString:
		var sb strings.Builder
		for _, part := range e.Parts {
			v, err := interp.evalExpr(part, env)
			if err != nil {
				sb.WriteString("{" + fmt.Sprintf("%v", err) + "}")
			} else {
				sb.WriteString(toStr(v))
			}
		}
		return sb.String(), nil
	case *ConcatExpr:
		l, err := interp.evalExpr(e.Left, env)
		if err != nil {
			return nil, err
		}
		r, err := interp.evalExpr(e.Right, env)
		if err != nil {
			return nil, err
		}
		return toStr(l) + toStr(r), nil
	case *BinaryExpr:
		return interp.evalBinary(e, env)
	case *UnaryExpr:
		operand, err := interp.evalExpr(e.Operand, env)
		if err != nil {
			return nil, err
		}
		if e.Op == "!" {
			return !isTruthy(operand), nil
		}
		if e.Op == "-" {
			return -toFloat(operand), nil
		}
	case *CaptureExpr:
		prompt, err := interp.evalExpr(e.Prompt, env)
		if err != nil {
			return nil, err
		}
		fmt.Print(toStr(prompt))
		line, _ := interp.reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), nil
	case *CallExpr:
		return interp.callFunc(e, env)
	case *ListLit:
		items := make([]interface{}, len(e.Elements))
		for i, el := range e.Elements {
			v, err := interp.evalExpr(el, env)
			if err != nil {
				return nil, err
			}
			items[i] = v
		}
		return items, nil
	case *MapLit:
		m := make(map[string]interface{})
		for i, k := range e.Keys {
			kv, err := interp.evalExpr(k, env)
			if err != nil {
				return nil, err
			}
			vv, err := interp.evalExpr(e.Values[i], env)
			if err != nil {
				return nil, err
			}
			m[toStr(kv)] = vv
		}
		return m, nil
	case *IndexExpr:
		lv, err := interp.evalExpr(e.List, env)
		if err != nil {
			return nil, err
		}
		iv, err := interp.evalExpr(e.Index, env)
		if err != nil {
			return nil, err
		}
		switch container := lv.(type) {
		case []interface{}:
			idx := int(toFloat(iv))
			if idx < 0 || idx >= len(container) {
				return nil, fmt.Errorf("index %d out of range (len %d)", idx, len(container))
			}
			return container[idx], nil
		case map[string]interface{}:
			return container[toStr(iv)], nil
		case string:
			idx := int(toFloat(iv))
			runes := []rune(container)
			if idx < 0 || idx >= len(runes) {
				return nil, fmt.Errorf("string index %d out of range", idx)
			}
			return string(runes[idx]), nil
		}
		return nil, fmt.Errorf("indexing non-indexable value")
	case *RunnerExpr:
		return interp.evalRunnerExpr(e, env)
	case *InlineFuncExpr:
		return &UserFunc{Params: e.Params, Body: e.Body, Env: env}, nil
	}
	return nil, fmt.Errorf("unknown expression: %T", expr)
}

func (interp *Interpreter) evalBinary(e *BinaryExpr, env *Env) (interface{}, error) {
	l, err := interp.evalExpr(e.Left, env)
	if err != nil {
		return nil, err
	}
	r, err := interp.evalExpr(e.Right, env)
	if err != nil {
		return nil, err
	}
	switch e.Op {
	case "+":
		if ls, ok := l.(string); ok {
			return ls + toStr(r), nil
		}
		if rs, ok := r.(string); ok {
			return toStr(l) + rs, nil
		}
		return toFloat(l) + toFloat(r), nil
	case "-":
		return toFloat(l) - toFloat(r), nil
	case "*":
		return toFloat(l) * toFloat(r), nil
	case "/":
		if toFloat(r) == 0 {
			return nil, fmt.Errorf("division by zero")
		}
		return toFloat(l) / toFloat(r), nil
	case "%":
		return math.Mod(toFloat(l), toFloat(r)), nil
	case "**":
		return math.Pow(toFloat(l), toFloat(r)), nil
	case "==":
		return l == r || toStr(l) == toStr(r), nil
	case "!=":
		return l != r && toStr(l) != toStr(r), nil
	case "<":
		return toFloat(l) < toFloat(r), nil
	case ">":
		return toFloat(l) > toFloat(r), nil
	case "<=":
		return toFloat(l) <= toFloat(r), nil
	case ">=":
		return toFloat(l) >= toFloat(r), nil
	case "&&":
		return isTruthy(l) && isTruthy(r), nil
	case "||":
		return isTruthy(l) || isTruthy(r), nil
	}
	return nil, fmt.Errorf("unknown operator %q", e.Op)
}

// ── Function calls ────────────────────────────────────────────────────────────

func (interp *Interpreter) callFunc(e *CallExpr, env *Env) (interface{}, error) {
	callee, ok := env.Get(e.Callee)
	if !ok {
		return interp.callBuiltin(e.Callee, e.Args, env)
	}
	fn, ok := callee.(*UserFunc)
	if !ok {
		return nil, fmt.Errorf("line %d: %q is not callable", e.Line, e.Callee)
	}
	args := make([]interface{}, len(e.Args))
	for i, a := range e.Args {
		v, err := interp.evalExpr(a, env)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	child := NewEnv(fn.Env)
	for i, p := range fn.Params {
		if i < len(args) {
			child.Set(p, args[i])
		} else {
			child.Set(p, nil)
		}
	}
	if err := interp.execBlock(fn.Body, child); err != nil {
		if ret, ok := err.(ReturnSignal); ok {
			return ret.Value, nil
		}
		return nil, err
	}
	return nil, nil
}

// ── Built-in functions ────────────────────────────────────────────────────────

func (interp *Interpreter) callBuiltin(name string, argExprs []Expr, env *Env) (interface{}, error) {
	args := make([]interface{}, len(argExprs))
	for i, a := range argExprs {
		v, err := interp.evalExpr(a, env)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	switch name {
	// ── Core
	case "len":
		if len(args) < 1 {
			return nil, fmt.Errorf("len() requires 1 arg")
		}
		switch v := args[0].(type) {
		case string:
			return float64(len([]rune(v))), nil
		case []interface{}:
			return float64(len(v)), nil
		case map[string]interface{}:
			return float64(len(v)), nil
		}
		return float64(0), nil
	case "str":
		if len(args) < 1 {
			return "", nil
		}
		return toStr(args[0]), nil
	case "num":
		if len(args) < 1 {
			return 0.0, nil
		}
		f, _ := strconv.ParseFloat(toStr(args[0]), 64)
		return f, nil
	case "bool":
		if len(args) < 1 {
			return false, nil
		}
		return isTruthy(args[0]), nil
	case "type":
		if len(args) < 1 {
			return "nil", nil
		}
		switch args[0].(type) {
		case string:
			return "string", nil
		case float64:
			return "number", nil
		case bool:
			return "bool", nil
		case []interface{}:
			return "list", nil
		case map[string]interface{}:
			return "map", nil
		case *UserFunc:
			return "func", nil
		}
		return "nil", nil
	// ── String
	case "split":
		if len(args) < 2 {
			return nil, fmt.Errorf("split() requires 2 args")
		}
		parts := strings.Split(toStr(args[0]), toStr(args[1]))
		res := make([]interface{}, len(parts))
		for i, p := range parts {
			res[i] = p
		}
		return res, nil
	case "join":
		if len(args) < 2 {
			return nil, fmt.Errorf("join() requires 2 args")
		}
		items, ok := args[0].([]interface{})
		if !ok {
			return toStr(args[0]), nil
		}
		parts := make([]string, len(items))
		for i, it := range items {
			parts[i] = toStr(it)
		}
		return strings.Join(parts, toStr(args[1])), nil
	case "upper":
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToUpper(toStr(args[0])), nil
	case "lower":
		if len(args) < 1 {
			return "", nil
		}
		return strings.ToLower(toStr(args[0])), nil
	case "trim":
		if len(args) < 1 {
			return "", nil
		}
		return strings.TrimSpace(toStr(args[0])), nil
	case "trimLeft":
		if len(args) < 1 {
			return "", nil
		}
		if len(args) >= 2 {
			return strings.TrimLeft(toStr(args[0]), toStr(args[1])), nil
		}
		return strings.TrimLeft(toStr(args[0]), " \t\n\r"), nil
	case "trimRight":
		if len(args) < 1 {
			return "", nil
		}
		if len(args) >= 2 {
			return strings.TrimRight(toStr(args[0]), toStr(args[1])), nil
		}
		return strings.TrimRight(toStr(args[0]), " \t\n\r"), nil
	case "contains":
		if len(args) < 2 {
			return false, nil
		}
		return strings.Contains(toStr(args[0]), toStr(args[1])), nil
	case "startsWith":
		if len(args) < 2 {
			return false, nil
		}
		return strings.HasPrefix(toStr(args[0]), toStr(args[1])), nil
	case "endsWith":
		if len(args) < 2 {
			return false, nil
		}
		return strings.HasSuffix(toStr(args[0]), toStr(args[1])), nil
	case "replace":
		if len(args) < 3 {
			return nil, fmt.Errorf("replace() requires 3 args")
		}
		return strings.ReplaceAll(toStr(args[0]), toStr(args[1]), toStr(args[2])), nil
	case "indexOf":
		if len(args) < 2 {
			return float64(-1), nil
		}
		return float64(strings.Index(toStr(args[0]), toStr(args[1]))), nil
	case "substr":
		if len(args) < 2 {
			return "", nil
		}
		s := toStr(args[0])
		runes := []rune(s)
		start := int(toFloat(args[1]))
		if start < 0 {
			start = 0
		}
		if start > len(runes) {
			return "", nil
		}
		if len(args) >= 3 {
			end := int(toFloat(args[2]))
			if end > len(runes) {
				end = len(runes)
			}
			return string(runes[start:end]), nil
		}
		return string(runes[start:]), nil
	case "repeat":
		if len(args) < 2 {
			return "", nil
		}
		return strings.Repeat(toStr(args[0]), int(toFloat(args[1]))), nil
	case "char":
		if len(args) < 1 {
			return "", nil
		}
		return string(rune(int(toFloat(args[0])))), nil
	case "code":
		if len(args) < 1 {
			return 0.0, nil
		}
		r := []rune(toStr(args[0]))
		if len(r) == 0 {
			return 0.0, nil
		}
		return float64(r[0]), nil
	// ── List
	case "append":
		if len(args) < 2 {
			return nil, fmt.Errorf("append() requires 2 args")
		}
		list, ok := args[0].([]interface{})
		if !ok {
			list = []interface{}{args[0]}
		}
		return append(list, args[1]), nil
	case "prepend":
		if len(args) < 2 {
			return nil, fmt.Errorf("prepend() requires 2 args")
		}
		list, ok := args[1].([]interface{})
		if !ok {
			list = []interface{}{args[1]}
		}
		return append([]interface{}{args[0]}, list...), nil
	case "pop":
		if len(args) < 1 {
			return nil, nil
		}
		list, ok := args[0].([]interface{})
		if !ok || len(list) == 0 {
			return nil, nil
		}
		return list[len(list)-1], nil
	case "shift":
		if len(args) < 1 {
			return nil, nil
		}
		list, ok := args[0].([]interface{})
		if !ok || len(list) == 0 {
			return nil, nil
		}
		return list[0], nil
	case "slice":
		if len(args) < 2 {
			return nil, fmt.Errorf("slice() requires list,start[,end]")
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return nil, nil
		}
		start := int(toFloat(args[1]))
		if start < 0 {
			start = 0
		}
		end := len(list)
		if len(args) >= 3 {
			end = int(toFloat(args[2]))
		}
		if end > len(list) {
			end = len(list)
		}
		return list[start:end], nil
	case "reverse":
		if len(args) < 1 {
			return nil, nil
		}
		switch v := args[0].(type) {
		case []interface{}:
			cp := make([]interface{}, len(v))
			copy(cp, v)
			for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
				cp[i], cp[j] = cp[j], cp[i]
			}
			return cp, nil
		case string:
			runes := []rune(v)
			for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
				runes[i], runes[j] = runes[j], runes[i]
			}
			return string(runes), nil
		}
		return args[0], nil
	case "unique":
		if len(args) < 1 {
			return nil, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return args[0], nil
		}
		seen := map[string]bool{}
		var out []interface{}
		for _, v := range list {
			k := toStr(v)
			if !seen[k] {
				seen[k] = true
				out = append(out, v)
			}
		}
		return out, nil
	case "flat":
		if len(args) < 1 {
			return nil, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return args[0], nil
		}
		var out []interface{}
		for _, v := range list {
			if sub, ok := v.([]interface{}); ok {
				out = append(out, sub...)
			} else {
				out = append(out, v)
			}
		}
		return out, nil
	case "range":
		if len(args) < 1 {
			return nil, fmt.Errorf("range() requires at least 1 arg")
		}
		start, end := 0.0, toFloat(args[0])
		if len(args) >= 2 {
			start = toFloat(args[0])
			end = toFloat(args[1])
		}
		step := 1.0
		if len(args) >= 3 {
			step = toFloat(args[2])
		}
		if step == 0 {
			step = 1
		}
		var res []interface{}
		for i := start; (step > 0 && i < end) || (step < 0 && i > end); i += step {
			res = append(res, i)
		}
		return res, nil
	case "keys":
		if len(args) < 1 {
			return nil, nil
		}
		m, ok := args[0].(map[string]interface{})
		if !ok {
			return nil, nil
		}
		ks := make([]interface{}, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		return ks, nil
	case "values":
		if len(args) < 1 {
			return nil, nil
		}
		m, ok := args[0].(map[string]interface{})
		if !ok {
			return nil, nil
		}
		vs := make([]interface{}, 0, len(m))
		for _, v := range m {
			vs = append(vs, v)
		}
		return vs, nil
	case "hasKey":
		if len(args) < 2 {
			return false, nil
		}
		m, ok := args[0].(map[string]interface{})
		if !ok {
			return false, nil
		}
		_, exists := m[toStr(args[1])]
		return exists, nil
	case "delete":
		if len(args) < 2 {
			return nil, nil
		}
		m, ok := args[0].(map[string]interface{})
		if !ok {
			return args[0], nil
		}
		delete(m, toStr(args[1]))
		return m, nil
	// ── Math
	case "abs":
		if len(args) < 1 {
			return 0.0, nil
		}
		return math.Abs(toFloat(args[0])), nil
	case "sqrt":
		if len(args) < 1 {
			return 0.0, nil
		}
		return math.Sqrt(toFloat(args[0])), nil
	case "pow":
		if len(args) < 2 {
			return 0.0, nil
		}
		return math.Pow(toFloat(args[0]), toFloat(args[1])), nil
	case "floor":
		if len(args) < 1 {
			return 0.0, nil
		}
		return math.Floor(toFloat(args[0])), nil
	case "ceil":
		if len(args) < 1 {
			return 0.0, nil
		}
		return math.Ceil(toFloat(args[0])), nil
	case "round":
		if len(args) < 1 {
			return 0.0, nil
		}
		return math.Round(toFloat(args[0])), nil
	case "min":
		if len(args) < 2 {
			return args[0], nil
		}
		a, b := toFloat(args[0]), toFloat(args[1])
		if a < b {
			return a, nil
		}
		return b, nil
	case "max":
		if len(args) < 2 {
			return args[0], nil
		}
		a, b := toFloat(args[0]), toFloat(args[1])
		if a > b {
			return a, nil
		}
		return b, nil
	case "rand":
		if len(args) < 1 {
			return rand.Float64(), nil
		}
		return float64(rand.Intn(int(toFloat(args[0])))), nil
	case "randFloat":
		return rand.Float64(), nil
	// ── I/O
	case "sleep":
		if len(args) >= 1 {
			time.Sleep(time.Duration(int(toFloat(args[0]))) * time.Millisecond)
		}
		return nil, nil
	case "exit":
		code := 0
		if len(args) > 0 {
			code = int(toFloat(args[0]))
		}
		os.Exit(code)
	case "env":
		if len(args) < 1 {
			return "", nil
		}
		return os.Getenv(toStr(args[0])), nil
	case "setEnv":
		if len(args) < 2 {
			return nil, nil
		}
		os.Setenv(toStr(args[0]), toStr(args[1]))
		return nil, nil
	case "args":
		a := os.Args
		res := make([]interface{}, len(a))
		for i, v := range a {
			res[i] = v
		}
		return res, nil
	// ── File I/O
	case "readFile":
		if len(args) < 1 {
			return nil, fmt.Errorf("readFile() requires a path")
		}
		data, err := os.ReadFile(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		return string(data), nil
	case "writeFile":
		if len(args) < 2 {
			return nil, fmt.Errorf("writeFile() requires path,content")
		}
		err := os.WriteFile(toStr(args[0]), []byte(toStr(args[1])), 0644)
		if err != nil {
			return nil, err
		}
		return true, nil
	case "appendFile":
		if len(args) < 2 {
			return nil, fmt.Errorf("appendFile() requires path,content")
		}
		f, err := os.OpenFile(toStr(args[0]), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		f.WriteString(toStr(args[1]))
		return true, nil
	case "exists":
		if len(args) < 1 {
			return false, nil
		}
		_, err := os.Stat(toStr(args[0]))
		return err == nil, nil
	case "listDir":
		if len(args) < 1 {
			return nil, fmt.Errorf("listDir() requires a path")
		}
		entries, err := os.ReadDir(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		res := make([]interface{}, len(entries))
		for i, e := range entries {
			res[i] = e.Name()
		}
		return res, nil
	case "mkdir":
		if len(args) < 1 {
			return nil, nil
		}
		return nil, os.MkdirAll(toStr(args[0]), 0755)
	case "removeFile":
		if len(args) < 1 {
			return nil, nil
		}
		return nil, os.Remove(toStr(args[0]))
	case "basename":
		if len(args) < 1 {
			return "", nil
		}
		return filepath.Base(toStr(args[0])), nil
	case "dirname":
		if len(args) < 1 {
			return "", nil
		}
		return filepath.Dir(toStr(args[0])), nil
	case "joinPath":
		parts := make([]string, len(args))
		for i, a := range args {
			parts[i] = toStr(a)
		}
		return filepath.Join(parts...), nil
	// ── JSON
	case "jsonParse":
		if len(args) < 1 {
			return nil, nil
		}
		var out interface{}
		if err := json.Unmarshal([]byte(toStr(args[0])), &out); err != nil {
			return nil, err
		}
		return convertJSON(out), nil
	case "jsonStr":
		if len(args) < 1 {
			return "null", nil
		}
		pretty := false
		if len(args) >= 2 {
			pretty = isTruthy(args[1])
		}
		var b []byte
		var err error
		if pretty {
			b, err = json.MarshalIndent(args[0], "", "  ")
		} else {
			b, err = json.Marshal(args[0])
		}
		if err != nil {
			return nil, err
		}
		return string(b), nil
	// ── Encoding
	case "base64enc":
		if len(args) < 1 {
			return "", nil
		}
		return base64.StdEncoding.EncodeToString([]byte(toStr(args[0]))), nil
	case "base64dec":
		if len(args) < 1 {
			return "", nil
		}
		b, err := base64.StdEncoding.DecodeString(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "urlEncode":
		if len(args) < 1 {
			return "", nil
		}
		return url.QueryEscape(toStr(args[0])), nil
	case "urlDecode":
		if len(args) < 1 {
			return "", nil
		}
		s, err := url.QueryUnescape(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		return s, nil
	case "hexEncode":
		if len(args) < 1 {
			return "", nil
		}
		return hex.EncodeToString([]byte(toStr(args[0]))), nil
	case "hexDecode":
		if len(args) < 1 {
			return "", nil
		}
		b, err := hex.DecodeString(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	// ── Crypto / Hashing
	case "md5":
		if len(args) < 1 {
			return "", nil
		}
		h := md5.Sum([]byte(toStr(args[0])))
		return hex.EncodeToString(h[:]), nil
	case "sha1":
		if len(args) < 1 {
			return "", nil
		}
		h := sha1.Sum([]byte(toStr(args[0])))
		return hex.EncodeToString(h[:]), nil
	case "sha256":
		if len(args) < 1 {
			return "", nil
		}
		h := sha256.Sum256([]byte(toStr(args[0])))
		return hex.EncodeToString(h[:]), nil
	// ── Regex
	case "regex":
		if len(args) < 2 {
			return nil, fmt.Errorf("regex() requires pattern,text")
		}
		re, err := regexp.Compile(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		matches := re.FindAllString(toStr(args[1]), -1)
		res := make([]interface{}, len(matches))
		for i, m := range matches {
			res[i] = m
		}
		return res, nil
	case "regexMatch":
		if len(args) < 2 {
			return false, nil
		}
		matched, err := regexp.MatchString(toStr(args[0]), toStr(args[1]))
		if err != nil {
			return false, nil
		}
		return matched, nil
	case "regexReplace":
		if len(args) < 3 {
			return nil, fmt.Errorf("regexReplace() requires pattern,repl,text")
		}
		re, err := regexp.Compile(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		return re.ReplaceAllString(toStr(args[2]), toStr(args[1])), nil
	// ── Network helpers
	case "resolve":
		if len(args) < 1 {
			return nil, nil
		}
		ips, err := net.LookupHost(toStr(args[0]))
		if err != nil {
			return nil, nil
		}
		res := make([]interface{}, len(ips))
		for i, ip := range ips {
			res[i] = ip
		}
		return res, nil
	case "lookupMX":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		mxs, err := net.LookupMX(toStr(args[0]))
		if err != nil {
			return []interface{}{}, nil
		}
		out := make([]interface{}, len(mxs))
		for i, m := range mxs {
			out[i] = m.Host
		}
		return out, nil
	case "lookupNS":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		nss, err := net.LookupNS(toStr(args[0]))
		if err != nil {
			return []interface{}{}, nil
		}
		out := make([]interface{}, len(nss))
		for i, n := range nss {
			out[i] = n.Host
		}
		return out, nil
	case "lookupTXT":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		txts, err := net.LookupTXT(toStr(args[0]))
		if err != nil {
			return []interface{}{}, nil
		}
		out := make([]interface{}, len(txts))
		for i, t := range txts {
			out[i] = t
		}
		return out, nil
	case "lookupCNAME":
		if len(args) < 1 {
			return "", nil
		}
		cname, err := net.LookupCNAME(toStr(args[0]))
		if err != nil {
			return "", nil
		}
		return cname, nil
	case "lookupAddr":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		names, err := net.LookupAddr(toStr(args[0]))
		if err != nil {
			return []interface{}{}, nil
		}
		out := make([]interface{}, len(names))
		for i, n := range names {
			out[i] = n
		}
		return out, nil
	case "hasPort":
		if len(args) < 2 {
			return false, nil
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", toStr(args[0]), int(toFloat(args[1]))), 500*time.Millisecond)
		if err != nil {
			return false, nil
		}
		conn.Close()
		return true, nil
	case "httpGet":
		// legacy: httpGet(url) → status code
		if len(args) < 1 {
			return nil, nil
		}
		r, err := interp.httpBuiltin("http", []interface{}{"GET", toStr(args[0])})
		if err != nil {
			return nil, nil
		}
		if m, ok := r.(map[string]interface{}); ok {
			return m["status"], nil
		}
		return nil, nil
	case "httpPost":
		// legacy: httpPost(url, body, ct?) → status code
		if len(args) < 2 {
			return nil, fmt.Errorf("httpPost() requires url,body")
		}
		opts := map[string]interface{}{"body": toStr(args[1])}
		if len(args) >= 3 {
			opts["type"] = toStr(args[2])
		}
		r, err := interp.httpBuiltin("http", []interface{}{"POST", toStr(args[0]), opts})
		if err != nil {
			return nil, err
		}
		if m, ok := r.(map[string]interface{}); ok {
			return m["status"], nil
		}
		return nil, nil
	case "http", "httpSession", "httpSessionSet", "httpSessionGet", "httpSessionPost",
		"httpSessionClose", "httpDo", "httpStatus", "httpBody", "httpHeaders", "httpHeader",
		"httpCookies", "httpCookie", "httpTime", "httpBrute", "httpFuzz", "httpMulti",
		"httpDownload", "extractLinks", "extractForms", "extractEmails", "extractTitle",
		"extractMeta", "stripHTML", "buildQuery", "parseQuery", "buildURL", "isRedirect":
		return interp.httpBuiltin(name, args)
	case "isIP":
		if len(args) < 1 {
			return false, nil
		}
		return net.ParseIP(toStr(args[0])) != nil, nil
	case "isCIDR":
		if len(args) < 1 {
			return false, nil
		}
		_, _, err := net.ParseCIDR(toStr(args[0]))
		return err == nil, nil
	case "cidrHosts":
		if len(args) < 1 {
			return nil, fmt.Errorf("cidrHosts() requires a CIDR")
		}
		_, ipnet, err := net.ParseCIDR(toStr(args[0]))
		if err != nil {
			return nil, err
		}
		var hosts []interface{}
		for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incrementIP(ip) {
			hosts = append(hosts, ip.String())
		}
		return hosts, nil
	// ── Time
	case "now":
		return float64(time.Now().Unix()), nil
	case "nowMs":
		return float64(time.Now().UnixMilli()), nil
	case "dateStr":
		if len(args) < 1 {
			return time.Now().Format("2006-01-02 15:04:05"), nil
		}
		return time.Unix(int64(toFloat(args[0])), 0).Format("2006-01-02 15:04:05"), nil
	case "timestamp":
		return time.Now().Format("20060102_150405"), nil
	// ── Misc
	// ── Hacking builtins ────────────────────────────────────────────────────
	case "wordlist", "commonPasswords", "hashType", "portServices", "payloadTypes", "encodings":
		return interp.hackingBuiltin(name, args)
	// Hacking functions usable directly (without do -->)
	case "Encode", "Decode", "HashIdentify", "PayloadGen", "CipherSolve", "SecretScan":
		return interp.hackingModule(name, args)
	// payloadList(type) → []string — GUI-friendly, no ANSI color codes
	case "payloadList":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		ps := getPayloads(strings.ToLower(toStr(args[0])))
		out := make([]interface{}, len(ps))
		for i, p := range ps {
			out[i] = p
		}
		return out, nil
	// stripAnsi(s) → removes ANSI escape codes from a string
	case "stripAnsi":
		if len(args) < 1 {
			return "", nil
		}
		s := toStr(args[0])
		ansiRe := regexp.MustCompile(`\x1b\[[0-9;]*m`)
		return ansiRe.ReplaceAllString(s, ""), nil
	// ── GUI builtins ─────────────────────────────────────────────────────────
	case "open.window", "end",
		"GUI.label", "GUI.input", "GUI.password", "GUI.number", "GUI.button",
		"GUI.iconButton", "GUI.link", "GUI.checkbox", "GUI.toggle", "GUI.radio",
		"GUI.dropdown", "GUI.slider", "GUI.progress", "GUI.spinner",
		"GUI.output", "GUI.image", "GUI.space", "GUI.divider",
		"GUI.table", "GUI.appendRow", "GUI.clearTable",
		"GUI.card", "GUI.cardEnd", "GUI.badge", "GUI.alert_box", "GUI.code",
		"GUI.tabs", "GUI.tabPanel", "GUI.tabPanelEnd", "GUI.openTab",
		"GUI.rowStart", "GUI.rowEnd", "GUI.colStart", "GUI.colEnd",
		"GUI.sidebar", "GUI.sidebarEnd", "GUI.header", "GUI.footer",
		"GUI.html", "GUI.on", "GUI.get", "GUI.set", "GUI.print", "GUI.println", "GUI.clear",
		"GUI.enable", "GUI.disable", "GUI.show", "GUI.hide", "GUI.focus",
		"GUI.notify", "GUI.alert", "GUI.confirm", "GUI.setTitle",
		"GUI.setProgress", "GUI.showSpinner", "GUI.hideSpinner",
		"GUI.setAccent", "GUI.setBg", "GUI.theme",
		"GUI.css", "GUI.addClass", "GUI.removeClass", "GUI.eval":
		return interp.guiBuiltin(name, args, argExprs, env)
	case "throw":
		if len(args) < 1 {
			return nil, &SpectatorError{Message: "error"}
		}
		return nil, &SpectatorError{Message: toStr(args[0])}
	case "print":
		parts := make([]string, len(args))
		for i, a := range args {
			parts[i] = toStr(a)
		}
		fmt.Print(strings.Join(parts, ""))
		return nil, nil
	case "input":
		if len(args) >= 1 {
			fmt.Print(toStr(args[0]))
		}
		line, _ := interp.reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), nil
	// ── New premium builtins
	case "format":
		if len(args) < 2 {
			return "", nil
		}
		fmtStr := toStr(args[0])
		fArgs := make([]interface{}, len(args)-1)
		for i, a := range args[1:] {
			fArgs[i] = a
		}
		return fmt.Sprintf(fmtStr, fArgs...), nil
	case "pad":
		if len(args) < 2 {
			return "", nil
		}
		s := toStr(args[0])
		width := int(toFloat(args[1]))
		if len(s) >= width {
			return s, nil
		}
		return s + strings.Repeat(" ", width-len(s)), nil
	case "padLeft":
		if len(args) < 2 {
			return "", nil
		}
		s := toStr(args[0])
		width := int(toFloat(args[1]))
		if len(s) >= width {
			return s, nil
		}
		return strings.Repeat(" ", width-len(s)) + s, nil
	case "lines":
		if len(args) < 1 {
			return nil, nil
		}
		ls := strings.Split(toStr(args[0]), "\n")
		res := make([]interface{}, len(ls))
		for i, l := range ls {
			res[i] = l
		}
		return res, nil
	case "words":
		if len(args) < 1 {
			return nil, nil
		}
		ws := strings.Fields(toStr(args[0]))
		res := make([]interface{}, len(ws))
		for i, w := range ws {
			res[i] = w
		}
		return res, nil
	case "parseInt":
		if len(args) < 1 {
			return 0.0, nil
		}
		base := 10
		if len(args) >= 2 {
			base = int(toFloat(args[1]))
		}
		n, err := strconv.ParseInt(strings.TrimSpace(toStr(args[0])), base, 64)
		if err != nil {
			return 0.0, nil
		}
		return float64(n), nil
	case "toHex":
		if len(args) < 1 {
			return "", nil
		}
		return fmt.Sprintf("%x", int64(toFloat(args[0]))), nil
	case "toBin":
		if len(args) < 1 {
			return "", nil
		}
		return fmt.Sprintf("%b", int64(toFloat(args[0]))), nil
	case "toOct":
		if len(args) < 1 {
			return "", nil
		}
		return fmt.Sprintf("%o", int64(toFloat(args[0]))), nil
	case "map":
		// map(list, funcName) — apply named user func to each element
		if len(args) < 2 {
			return nil, fmt.Errorf("map() requires list,funcName")
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return nil, fmt.Errorf("map(): first arg must be list")
		}
		fnName := toStr(args[1])
		out := make([]interface{}, 0, len(list))
		for _, item := range list {
			callExpr := &CallExpr{Callee: fnName, Args: []Expr{&StringLit{Value: toStr(item)}}, Line: 0}
			// resolve as builtin directly with item
			result, err := interp.callBuiltin(fnName, []Expr{&StringLit{Value: toStr(item)}}, interp.global)
			if err != nil {
				// try user func via callExpr
				result2, err2 := interp.callFunc(callExpr, interp.global)
				if err2 != nil {
					return nil, err2
				}
				out = append(out, result2)
			} else {
				out = append(out, result)
			}
			_ = callExpr
		}
		return out, nil
	case "filter":
		if len(args) < 2 {
			return nil, fmt.Errorf("filter() requires list,pattern")
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return nil, fmt.Errorf("filter(): first arg must be list")
		}
		pattern := toStr(args[1])
		var out []interface{}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		for _, item := range list {
			if re.MatchString(toStr(item)) {
				out = append(out, item)
			}
		}
		return out, nil
	case "sortList":
		if len(args) < 1 {
			return nil, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return args[0], nil
		}
		cp := make([]interface{}, len(list))
		copy(cp, list)
		// simple insertion sort
		for i := 1; i < len(cp); i++ {
			j := i
			for j > 0 && toStr(cp[j-1]) > toStr(cp[j]) {
				cp[j-1], cp[j] = cp[j], cp[j-1]
				j--
			}
		}
		return cp, nil
	case "sum":
		if len(args) < 1 {
			return 0.0, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return toFloat(args[0]), nil
		}
		total := 0.0
		for _, v := range list {
			total += toFloat(v)
		}
		return total, nil
	case "avg":
		if len(args) < 1 {
			return 0.0, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return toFloat(args[0]), nil
		}
		if len(list) == 0 {
			return 0.0, nil
		}
		total := 0.0
		for _, v := range list {
			total += toFloat(v)
		}
		return total / float64(len(list)), nil
	case "zip":
		if len(args) < 2 {
			return nil, fmt.Errorf("zip() requires two lists")
		}
		a, aOk := args[0].([]interface{})
		b, bOk := args[1].([]interface{})
		if !aOk || !bOk {
			return nil, fmt.Errorf("zip(): both args must be lists")
		}
		n := len(a)
		if len(b) < n {
			n = len(b)
		}
		out := make([]interface{}, n)
		for i := 0; i < n; i++ {
			out[i] = []interface{}{a[i], b[i]}
		}
		return out, nil
	case "confirm":
		prompt := "Continue? (y/n): "
		if len(args) >= 1 {
			prompt = toStr(args[0])
		}
		fmt.Print(colorYellow(prompt))
		line, _ := interp.reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		return strings.ToLower(line) == "y" || strings.ToLower(line) == "yes", nil
	case "clearScreen":
		fmt.Print("[2J[H")
		return nil, nil
	case "bold":
		if len(args) < 1 {
			return "", nil
		}
		return colorBold(toStr(args[0])), nil
	case "red":
		if len(args) < 1 {
			return "", nil
		}
		return colorRed(toStr(args[0])), nil
	case "green":
		if len(args) < 1 {
			return "", nil
		}
		return colorGreen(toStr(args[0])), nil
	case "cyan":
		if len(args) < 1 {
			return "", nil
		}
		return colorCyan(toStr(args[0])), nil
	case "yellow":
		if len(args) < 1 {
			return "", nil
		}
		return colorYellow(toStr(args[0])), nil
	case "magenta":
		if len(args) < 1 {
			return "", nil
		}
		return colorMagenta(toStr(args[0])), nil
	// ── Mission lifecycle ────────────────────────────────────────────────
	case "missionStart", "missionStage", "missionFind", "missionNote",
		"missionData", "missionGet", "missionEnd", "missionReport",
		"missionFindings", "missionSummary":
		return interp.missionBuiltin(name, args)
	// ── Pipeline & display utilities ─────────────────────────────────────
	case "pipe", "progress", "table", "tally", "diff", "intersect",
		"gather", "banner", "truncate", "colorize",
		"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return interp.pipelineBuiltin(name, args, argExprs, env)
	}
	return nil, fmt.Errorf("undefined function %q", name)
}

// ── Module dispatch ────────────────────────────────────────────────────────────

func (interp *Interpreter) callModule(name string, args []interface{}) (interface{}, error) {
	switch name {
	case "Recon":
		if len(args) < 1 {
			return nil, fmt.Errorf("Recon requires target")
		}
		return interp.moduleRecon(toStr(args[0]))
	case "PortScan":
		if len(args) < 1 {
			return nil, fmt.Errorf("PortScan requires target")
		}
		s, e := 1, 1024
		if len(args) >= 2 {
			s = int(toFloat(args[1]))
		}
		if len(args) >= 3 {
			e = int(toFloat(args[2]))
		}
		return interp.modulePortScan(toStr(args[0]), s, e)
	case "DNSLookup":
		if len(args) < 1 {
			return nil, fmt.Errorf("DNSLookup requires domain")
		}
		return interp.moduleDNS(toStr(args[0]))
	case "WHOIs":
		if len(args) < 1 {
			return nil, fmt.Errorf("WHOIs requires domain")
		}
		return interp.moduleWHOIs(toStr(args[0]))
	case "HTTPProbe":
		if len(args) < 1 {
			return nil, fmt.Errorf("HTTPProbe requires URL")
		}
		return interp.moduleHTTPProbe(toStr(args[0]))
	case "SubdomainEnum":
		if len(args) < 1 {
			return nil, fmt.Errorf("SubdomainEnum requires domain")
		}
		return interp.moduleSubdomainEnum(toStr(args[0]))
	case "BannerGrab":
		if len(args) < 2 {
			return nil, fmt.Errorf("BannerGrab requires host,port")
		}
		return interp.moduleBannerGrab(toStr(args[0]), int(toFloat(args[1])))
	case "PingCheck":
		if len(args) < 1 {
			return nil, fmt.Errorf("PingCheck requires target")
		}
		return interp.modulePing(toStr(args[0]))
	case "Headers":
		if len(args) < 1 {
			return nil, fmt.Errorf("Headers requires URL")
		}
		return interp.moduleHeaders(toStr(args[0]))
	case "OSInfo":
		return interp.moduleOSInfo()
	case "Run":
		if len(args) < 1 {
			return nil, fmt.Errorf("Run requires command")
		}
		return interp.moduleRun(toStr(args[0]))
	// ── Hacking modules ─────────────────────────────────────────────────────
	case "PayloadGen", "Encode", "Decode", "HashIdentify", "Crack",
		"HeaderAudit", "CORSTest", "OpenRedirect", "SecretScan", "JWT",
		"SubTakeover", "IPInfo", "CMDInject", "PathTraversal", "CipherSolve":
		return interp.hackingModule(name, args)
	// ── New modules
	case "SSLInfo":
		if len(args) < 1 {
			return nil, fmt.Errorf("SSLInfo requires host")
		}
		return interp.moduleSSLInfo(toStr(args[0]))
	case "CIDRScan":
		if len(args) < 2 {
			return nil, fmt.Errorf("CIDRScan requires cidr,port")
		}
		return interp.moduleCIDRScan(toStr(args[0]), int(toFloat(args[1])))
	case "FuzzURL":
		if len(args) < 2 {
			return nil, fmt.Errorf("FuzzURL requires url,wordlist")
		}
		return interp.moduleFuzzURL(toStr(args[0]), args[1])
	case "CryptoHash":
		if len(args) < 2 {
			return nil, fmt.Errorf("CryptoHash requires algo,data")
		}
		return interp.moduleCryptoHash(toStr(args[0]), toStr(args[1]))
	case "SQLiTest":
		if len(args) < 1 {
			return nil, fmt.Errorf("SQLiTest requires url")
		}
		return interp.moduleSQLiTest(toStr(args[0]))
	case "DirBust":
		if len(args) < 1 {
			return nil, fmt.Errorf("DirBust requires url")
		}
		return interp.moduleDirBust(toStr(args[0]))
	case "ConcurrentScan":
		if len(args) < 2 {
			return nil, fmt.Errorf("ConcurrentScan requires hosts,port")
		}
		return interp.moduleConcurrentScan(args[0], int(toFloat(args[1])))
	case "GeoIP":
		if len(args) < 1 {
			return nil, fmt.Errorf("GeoIP requires ip")
		}
		return interp.moduleGeoIP(toStr(args[0]))
	case "EmailHarvest":
		if len(args) < 1 {
			return nil, fmt.Errorf("EmailHarvest requires url")
		}
		return interp.moduleEmailHarvest(toStr(args[0]))
	case "TechDetect":
		if len(args) < 1 {
			return nil, fmt.Errorf("TechDetect requires url")
		}
		return interp.moduleTechDetect(toStr(args[0]))
	// ── New premium modules
	case "HTTPRequest":
		method := "GET"
		if len(args) >= 1 {
			method = toStr(args[0])
		}
		rawURL := ""
		if len(args) >= 2 {
			rawURL = toStr(args[1])
		}
		body := ""
		if len(args) >= 3 {
			body = toStr(args[2])
		}
		headers := ""
		if len(args) >= 4 {
			headers = toStr(args[3])
		}
		return interp.moduleHTTPRequest(method, rawURL, body, headers)
	case "NetSweep":
		if len(args) < 1 {
			return nil, fmt.Errorf("NetSweep requires CIDR and port list")
		}
		cidr := toStr(args[0])
		var ports []int
		if len(args) >= 2 {
			switch pv := args[1].(type) {
			case []interface{}:
				for _, p := range pv {
					ports = append(ports, int(toFloat(p)))
				}
			default:
				ports = []int{int(toFloat(args[1]))}
			}
		} else {
			ports = []int{80, 443, 22, 8080}
		}
		return interp.moduleNetSweep(cidr, ports)
	case "SSLScan":
		if len(args) < 1 {
			return nil, fmt.Errorf("SSLScan requires host")
		}
		return interp.moduleSSLScan(toStr(args[0]))
	case "SaveOutput":
		if len(args) < 2 {
			return nil, fmt.Errorf("SaveOutput requires filename,content")
		}
		return interp.moduleSaveOutput(toStr(args[0]), toStr(args[1]))
	case "ColorPrint":
		if len(args) < 2 {
			return nil, fmt.Errorf("ColorPrint requires color,text")
		}
		return interp.moduleColorPrint(toStr(args[0]), toStr(args[1]))
	case "Table":
		if len(args) < 2 {
			return nil, fmt.Errorf("Table requires headers,rows")
		}
		return interp.moduleTable(args[0], args[1])
	case "Progress":
		if len(args) < 3 {
			return nil, fmt.Errorf("Progress requires label,total,current")
		}
		return interp.moduleProgress(toStr(args[0]), int(toFloat(args[1])), int(toFloat(args[2])))
	case "Spinner":
		if len(args) < 1 {
			return nil, fmt.Errorf("Spinner requires label")
		}
		ms := 2000
		if len(args) >= 2 {
			ms = int(toFloat(args[1]))
		}
		return interp.moduleSpinner(toStr(args[0]), ms)
	}
	return nil, fmt.Errorf("unknown module %q  — run `spectator --help` for list", name)
}

func (interp *Interpreter) execImport(s *ImportStmt) error {
	libName := s.Library
	// Built-in modules — no file needed
	builtins := map[string]bool{
		"GUI": true, "Spec.GUI": true,
		"GUI.window": true, "Spec": true,
	}
	if builtins[libName] {
		return nil
	}

	home, _ := os.UserHomeDir()
	paths := []string{
		libName + ".str", libName + "/index.str",
		home + "/.space/libs/" + libName + ".str",
		home + "/.space/libs/" + libName + "/index.str",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		lx := NewLexer(string(data))
		tokens, err := lx.Tokenize()
		if err != nil {
			return fmt.Errorf("import %q: %w", libName, err)
		}
		pr := NewParser(tokens)
		prog, err := pr.Parse()
		if err != nil {
			return fmt.Errorf("import %q: %w", libName, err)
		}
		interp.libs[libName] = true
		return interp.Run(prog)
	}
	return fmt.Errorf("library %q not found", libName)
}

// ── Module implementations ────────────────────────────────────────────────────

func (interp *Interpreter) moduleRecon(target string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] Recon → " + target + "\n"))
	if addrs, err := net.LookupHost(target); err == nil {
		sb.WriteString(colorGreen("  [IP]    ") + strings.Join(addrs, ", ") + "\n")
	} else {
		sb.WriteString(colorRed("  [IP]    resolve failed\n"))
	}
	if mxs, err := net.LookupMX(target); err == nil {
		for _, mx := range mxs {
			sb.WriteString(colorCyan("  [MX]    ") + mx.Host + "\n")
		}
	}
	if nss, err := net.LookupNS(target); err == nil {
		for _, ns := range nss {
			sb.WriteString(colorYellow("  [NS]    ") + ns.Host + "\n")
		}
	}
	if txts, err := net.LookupTXT(target); err == nil {
		for _, txt := range txts {
			sb.WriteString(colorMagenta("  [TXT]   ") + txt + "\n")
		}
	}
	if cname, err := net.LookupCNAME(target); err == nil && cname != target+"." {
		sb.WriteString(colorCyan("  [CNAME] ") + cname + "\n")
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) modulePortScan(target string, start, end int) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] PortScan → %s (%d–%d)\n", target, start, end)))
	open := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100) // 100 concurrent
	results := make([]string, 0)
	for port := start; port <= end; port++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, p), 300*time.Millisecond)
			if err == nil {
				conn.Close()
				svc := knownPort(p)
				mu.Lock()
				results = append(results, colorGreen(fmt.Sprintf("  [OPEN] %d/tcp   %s\n", p, svc)))
				open++
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	for _, r := range results {
		sb.WriteString(r)
	}
	if open == 0 {
		sb.WriteString(colorRed("  No open ports.\n"))
	}
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] Done — %d open port(s).\n", open)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleDNS(domain string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] DNSLookup → " + domain + "\n"))
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		sb.WriteString(colorGreen("  " + ip + "\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleWHOIs(domain string) (interface{}, error) {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	fmt.Fprintf(conn, "%s\r\n", domain)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	result := sb.String()
	if len(result) > 600 {
		result = result[:600] + "\n  [...truncated...]"
	}
	return colorBold("[*] WHOIs → "+domain+"\n") + colorGreen(result), nil
}

func (interp *Interpreter) moduleHTTPProbe(rawURL string) (interface{}, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var sb strings.Builder
	sb.WriteString(colorBold("[*] HTTPProbe → " + rawURL + "\n"))
	sb.WriteString(colorGreen(fmt.Sprintf("  Status    : %s\n", resp.Status)))
	sb.WriteString(colorCyan(fmt.Sprintf("  Proto     : %s\n", resp.Proto)))
	for _, h := range []string{"Server", "X-Powered-By", "Content-Type", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "Access-Control-Allow-Origin", "Content-Security-Policy"} {
		if v := resp.Header.Get(h); v != "" {
			sb.WriteString(colorYellow(fmt.Sprintf("  %-38s %s\n", h+":", v)))
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSubdomainEnum(domain string) (interface{}, error) {
	wordlist := []string{"www", "mail", "ftp", "dev", "test", "staging", "api", "admin", "vpn", "remote", "portal", "beta", "git", "ci", "cdn", "static", "media", "shop", "store", "app", "dashboard", "monitor", "smtp", "pop", "imap", "docs", "help", "status", "auth", "login", "secure", "blog", "forum", "news", "support", "m", "mobile", "ns1", "ns2", "mx", "smtp", "webmail", "cpanel", "whm", "autodiscover"}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SubdomainEnum → " + domain + "\n"))
	found := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sub := range wordlist {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			fqdn := s + "." + domain
			if _, err := net.LookupHost(fqdn); err == nil {
				mu.Lock()
				sb.WriteString(colorGreen("  [FOUND] " + fqdn + "\n"))
				found++
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	if found == 0 {
		sb.WriteString(colorRed("  No subdomains resolved from wordlist.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleBannerGrab(host string, port int) (interface{}, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	if banner == "" {
		banner = "(no banner received)"
	}
	return colorBold(fmt.Sprintf("[*] BannerGrab → %s:%d\n", host, port)) + colorGreen("  "+banner), nil
}

func (interp *Interpreter) modulePing(target string) (interface{}, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "3", target)
	} else {
		cmd = exec.Command("ping", "-c", "3", "-W", "1", target)
	}
	out, err := cmd.CombinedOutput()
	status := colorGreen("  [ALIVE] ")
	if err != nil {
		status = colorRed("  [UNREACHABLE] ")
	}
	summary := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "rtt") || strings.Contains(l, "avg") || strings.Contains(l, "Average") {
			summary = "  " + strings.TrimSpace(l)
		}
	}
	return colorBold("[*] PingCheck → "+target+"\n") + status + target + "\n" + colorCyan(summary), nil
}

func (interp *Interpreter) moduleHeaders(rawURL string) (interface{}, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var sb strings.Builder
	sb.WriteString(colorBold("[*] Headers → " + rawURL + "\n"))
	for k, vs := range resp.Header {
		sb.WriteString(colorYellow(fmt.Sprintf("  %-35s %s\n", k+":", strings.Join(vs, ", "))))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleOSInfo() (interface{}, error) {
	hostname, _ := os.Hostname()
	ifs, _ := net.Interfaces()
	var ifstrs []string
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ifstrs = append(ifstrs, fmt.Sprintf("%s(%s)", iface.Name, a.String()))
			}
		}
	}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] OSInfo\n"))
	sb.WriteString(colorGreen(fmt.Sprintf("  OS       : %s/%s\n", runtime.GOOS, runtime.GOARCH)))
	sb.WriteString(colorCyan(fmt.Sprintf("  Hostname : %s\n", hostname)))
	sb.WriteString(colorYellow(fmt.Sprintf("  CPUs     : %d\n", runtime.NumCPU())))
	sb.WriteString(colorMagenta(fmt.Sprintf("  Ifaces   : %s\n", strings.Join(ifstrs, "  "))))
	wd, _ := os.Getwd()
	sb.WriteString(colorGreen(fmt.Sprintf("  CWD      : %s\n", wd)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleRun(command string) (interface{}, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		return colorRed("[!] " + result), nil
	}
	return result, nil
}

// ── New module implementations ─────────────────────────────────────────────────

func (interp *Interpreter) moduleSSLInfo(host string) (interface{}, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	// Use tcp connection + TLS check via curl-like approach
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SSLInfo → " + host + "\n"))
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %v", err)
	}
	conn.Close()
	sb.WriteString(colorGreen("  [+] Port 443 open — TLS likely active\n"))
	// Get cert info via openssl if available
	parts := strings.Split(host, ":")
	cmd := exec.Command("openssl", "s_client", "-connect", host, "-servername", parts[0])
	cmd.Stdin = strings.NewReader("")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	for _, line := range strings.Split(outStr, "\n") {
		lt := strings.TrimSpace(line)
		if strings.Contains(lt, "subject") || strings.Contains(lt, "issuer") || strings.Contains(lt, "Not Before") || strings.Contains(lt, "Not After") {
			sb.WriteString(colorCyan("  " + lt + "\n"))
		}
	}
	if !strings.Contains(outStr, "subject") {
		sb.WriteString(colorYellow("  (install openssl for full cert details)\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleCIDRScan(cidr string, port int) (interface{}, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] CIDRScan → %s port %d\n", cidr, port)))
	var mu sync.Mutex
	var wg sync.WaitGroup
	alive := 0
	sem := make(chan struct{}, 200)
	for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incrementIP(ip) {
		ipStr := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, port), 300*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				sb.WriteString(colorGreen("  [UP] " + h + "\n"))
				alive++
				mu.Unlock()
			}
		}(ipStr)
	}
	wg.Wait()
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] %d host(s) with port %d open.\n", alive, port)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleFuzzURL(baseURL string, wordlistVal interface{}) (interface{}, error) {
	wordlist := []string{"admin", "login", "dashboard", "config", "backup", "uploads", "api", "v1", "v2", "test", "dev", ".git", "wp-admin", "phpinfo.php", "shell.php", "robots.txt", "sitemap.xml", ".env", "config.php", "database.php"}
	if wl, ok := wordlistVal.([]interface{}); ok {
		wordlist = make([]string, len(wl))
		for i, w := range wl {
			wordlist[i] = toStr(w)
		}
	}
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	var sb strings.Builder
	sb.WriteString(colorBold("[*] FuzzURL → " + baseURL + "\n"))
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	found := 0
	for _, word := range wordlist {
		targetURL := baseURL + "/" + word
		resp, err := client.Get(targetURL)
		if err != nil {
			continue
		}
		resp.Body.Close()
		code := resp.StatusCode
		if code != 404 && code != 0 {
			color := colorGreen
			if code >= 300 && code < 400 {
				color = colorYellow
			}
			if code >= 400 {
				color = colorRed
			}
			sb.WriteString(color(fmt.Sprintf("  [%d] %s\n", code, targetURL)))
			found++
		}
	}
	if found == 0 {
		sb.WriteString(colorRed("  No interesting paths found.\n"))
	}
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] Fuzz complete — %d paths found.\n", found)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleCryptoHash(algo, data string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] CryptoHash → " + algo + "\n"))
	sb.WriteString(colorCyan("  Input  : ") + data + "\n")
	switch strings.ToLower(algo) {
	case "md5":
		h := md5.Sum([]byte(data))
		sb.WriteString(colorGreen("  MD5    : ") + hex.EncodeToString(h[:]) + "\n")
	case "sha1":
		h := sha1.Sum([]byte(data))
		sb.WriteString(colorGreen("  SHA1   : ") + hex.EncodeToString(h[:]) + "\n")
	case "sha256":
		h := sha256.Sum256([]byte(data))
		sb.WriteString(colorGreen("  SHA256 : ") + hex.EncodeToString(h[:]) + "\n")
	case "all":
		h1 := md5.Sum([]byte(data))
		sb.WriteString(colorGreen("  MD5    : ") + hex.EncodeToString(h1[:]) + "\n")
		h2 := sha1.Sum([]byte(data))
		sb.WriteString(colorYellow("  SHA1   : ") + hex.EncodeToString(h2[:]) + "\n")
		h3 := sha256.Sum256([]byte(data))
		sb.WriteString(colorCyan("  SHA256 : ") + hex.EncodeToString(h3[:]) + "\n")
	default:
		return nil, fmt.Errorf("unknown algo %q (use md5/sha1/sha256/all)", algo)
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSQLiTest(targetURL string) (interface{}, error) {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	payloads := []string{"'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1", "'; DROP TABLE users--", "1 AND 1=2", "1' AND '1'='1"}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SQLiTest → " + targetURL + "\n"))
	client := &http.Client{Timeout: 5 * time.Second}
	errors_found := 0
	dbErrors := []string{"sql syntax", "mysql", "sqlite", "postgresql", "ora-", "microsoft sql", "odbc driver", "syntax error"}
	for _, payload := range payloads {
		testURL := targetURL
		if strings.Contains(testURL, "=") {
			parts := strings.SplitN(testURL, "=", 2)
			testURL = parts[0] + "=" + url.QueryEscape(payload)
		}
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		body := strings.ToLower(string(buf[:n]))
		for _, dbErr := range dbErrors {
			if strings.Contains(body, dbErr) {
				sb.WriteString(colorRed(fmt.Sprintf("  [VULN!] Payload: %s → DB error in response\n", payload)))
				errors_found++
				break
			}
		}
	}
	if errors_found == 0 {
		sb.WriteString(colorGreen("  [OK] No obvious SQLi error-based indicators found.\n"))
	} else {
		sb.WriteString(colorRed(fmt.Sprintf("  [!] %d potential SQLi indicator(s) found! Verify manually.\n", errors_found)))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleDirBust(baseURL string) (interface{}, error) {
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	wordlist := []string{"admin", "login", "wp-admin", "dashboard", "config", "backup", "uploads", "api", "v1", "v2", "test", "dev", ".git", "phpinfo.php", "robots.txt", "sitemap.xml", ".env", "config.php", "db.php", "database.php", "shell.php", "cmd.php", "info.php", "readme", "README", "CHANGELOG", "LICENSE", "server-status", "server-info", "manager", "console", "portal", "user", "users", "account", "accounts", "static", "assets", "images", "js", "css", "files", "docs", "documentation", "swagger", "swagger-ui", "graphql", "health", "status", "metrics"}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] DirBust → " + baseURL + "\n"))
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := 0
	sem := make(chan struct{}, 30)
	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			u := baseURL + "/" + w
			resp, err := client.Get(u)
			if err != nil {
				return
			}
			resp.Body.Close()
			code := resp.StatusCode
			if code != 404 {
				color := colorGreen
				if code >= 300 && code < 400 {
					color = colorYellow
				}
				if code >= 500 {
					color = colorRed
				}
				mu.Lock()
				sb.WriteString(color(fmt.Sprintf("  [%d] /%s\n", code, w)))
				found++
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	if found == 0 {
		sb.WriteString(colorRed("  Nothing found.\n"))
	}
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] DirBust complete — %d path(s) found.\n", found)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleConcurrentScan(hostsVal interface{}, port int) (interface{}, error) {
	var hosts []string
	switch v := hostsVal.(type) {
	case []interface{}:
		for _, h := range v {
			hosts = append(hosts, toStr(h))
		}
	case string:
		hosts = []string{v}
	}
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] ConcurrentScan → %d hosts, port %d\n", len(hosts), port)))
	var mu sync.Mutex
	var wg sync.WaitGroup
	alive := 0
	sem := make(chan struct{}, 200)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, port), 400*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				sb.WriteString(colorGreen(fmt.Sprintf("  [OPEN] %s:%d\n", h, port)))
				alive++
				mu.Unlock()
			} else {
				mu.Lock()
				sb.WriteString(colorRed(fmt.Sprintf("  [CLOSED] %s:%d\n", h, port)))
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] %d/%d host(s) have port %d open.\n", alive, len(hosts), port)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleGeoIP(ip string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] GeoIP → " + ip + "\n"))
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	var data map[string]interface{}
	if err := json.Unmarshal(buf[:n], &data); err != nil {
		return nil, err
	}
	fields := []string{"country", "regionName", "city", "zip", "isp", "org", "as", "query"}
	for _, f := range fields {
		if v, ok := data[f]; ok && v != "" {
			sb.WriteString(colorGreen(fmt.Sprintf("  %-12s : %v\n", f, v)))
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleEmailHarvest(rawURL string) (interface{}, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] EmailHarvest → " + rawURL + "\n"))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024*512)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	emails := re.FindAllString(body, -1)
	seen := map[string]bool{}
	found := 0
	for _, e := range emails {
		if !seen[e] {
			seen[e] = true
			sb.WriteString(colorGreen("  [+] " + e + "\n"))
			found++
		}
	}
	if found == 0 {
		sb.WriteString(colorRed("  No email addresses found on page.\n"))
	}
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] %d unique email(s) harvested.\n", found)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleTechDetect(rawURL string) (interface{}, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] TechDetect → " + rawURL + "\n"))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 512*1024)
	n, _ := resp.Body.Read(buf)
	body := strings.ToLower(string(buf[:n]))
	// Check headers
	server := resp.Header.Get("Server")
	if server != "" {
		sb.WriteString(colorGreen("  [Server]      " + server + "\n"))
	}
	powered := resp.Header.Get("X-Powered-By")
	if powered != "" {
		sb.WriteString(colorCyan("  [Powered-By]  " + powered + "\n"))
	}
	// Check body for tech fingerprints
	tech := map[string]string{
		"wp-content": "WordPress", "wp-login": "WordPress",
		"joomla": "Joomla", "drupal": "Drupal",
		"laravel": "Laravel", "symfony": "Symfony",
		"react": "React.js", "vue.js": "Vue.js", "angular": "Angular",
		"jquery": "jQuery", "bootstrap": "Bootstrap",
		"nginx": "Nginx", "apache": "Apache",
		"php": "PHP", "asp.net": "ASP.NET", "flask": "Flask", "django": "Django",
		"cloudflare": "Cloudflare", "akamai": "Akamai",
	}
	detected := map[string]bool{}
	for sig, name := range tech {
		if strings.Contains(body, sig) && !detected[name] {
			sb.WriteString(colorYellow("  [+] " + name + "\n"))
			detected[name] = true
		}
	}
	// Check cookies
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "php") {
			sb.WriteString(colorMagenta("  [Cookie] PHP session detected\n"))
		}
		if strings.Contains(strings.ToLower(cookie.Name), "asp") {
			sb.WriteString(colorMagenta("  [Cookie] ASP.NET session detected\n"))
		}
	}
	if len(detected) == 0 && server == "" && powered == "" {
		sb.WriteString(colorRed("  No technologies detected.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func toStr(v interface{}) string {
	if v == nil {
		return "nil"
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == math.Trunc(val) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case []interface{}:
		parts := make([]string, len(val))
		for i, it := range val {
			parts[i] = toStr(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]interface{}:
		b, _ := json.Marshal(val)
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case bool:
		if val {
			return 1
		}
		return 0
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

func isTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case string:
		return val != ""
	case []interface{}:
		return len(val) > 0
	case map[string]interface{}:
		return len(val) > 0
	}
	return true
}

func knownPort(port int) string {
	m := map[int]string{21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 27017: "MongoDB", 3389: "RDP", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached", 5000: "Flask/Dev", 8000: "HTTP-Dev", 9000: "PHP-FPM", 2375: "Docker", 2376: "Docker-TLS", 6443: "Kubernetes", 10250: "Kubelet"}
	if s, ok := m[port]; ok {
		return s
	}
	return ""
}

func cloneIP(ip net.IP) net.IP { clone := make(net.IP, len(ip)); copy(clone, ip); return clone }
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func convertJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{})
		for k, vv := range val {
			out[k] = convertJSON(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = convertJSON(vv)
		}
		return out
	}
	return v
}

// color helpers are defined in colors.go

// ── NEW POWERFUL MODULES (appended) ──────────────────────────────────────────

func (interp *Interpreter) moduleHTTPRequest(method, rawURL, body, headers string) (interface{}, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req, err := http.NewRequest(strings.ToUpper(method), rawURL, bodyReader)
	if err != nil {
		return nil, err
	}
	// Parse custom headers "Key:Val,Key2:Val2"
	if headers != "" {
		for _, h := range strings.Split(headers, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}
	req.Header.Set("User-Agent", "Spectator/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 1024*512)
	n, _ := resp.Body.Read(buf)
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] HTTPRequest → %s %s\n", strings.ToUpper(method), rawURL)))
	sb.WriteString(colorGreen(fmt.Sprintf("  Status  : %s\n", resp.Status)))
	for k, vs := range resp.Header {
		sb.WriteString(colorCyan(fmt.Sprintf("  %-30s %s\n", k+":", strings.Join(vs, ", "))))
	}
	if n > 0 {
		preview := string(buf[:n])
		if len(preview) > 800 {
			preview = preview[:800] + "\n  [... truncated ...]"
		}
		sb.WriteString(colorYellow("\n  Body:\n") + preview + "\n")
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleNetSweep(cidr string, ports []int) (interface{}, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}
	var hosts []string
	for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incrementIP(ip) {
		hosts = append(hosts, ip.String())
	}
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] NetSweep → %s (%d hosts, %d port(s))\n", cidr, len(hosts), len(ports))))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 300)
	alive := 0
	for _, h := range hosts {
		for _, p := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(host string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 400*time.Millisecond)
				if err == nil {
					conn.Close()
					svc := knownPort(port)
					mu.Lock()
					sb.WriteString(colorGreen(fmt.Sprintf("  [+] %s:%d  %s\n", host, port, svc)))
					alive++
					mu.Unlock()
				}
			}(h, p)
		}
	}
	wg.Wait()
	if alive == 0 {
		sb.WriteString(colorRed("  No open ports found.\n"))
	}
	sb.WriteString(colorYellow(fmt.Sprintf("  [*] Sweep complete — %d open service(s) found.\n", alive)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSSLScan(host string) (interface{}, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SSLScan → " + host + "\n"))
	conn, err := net.DialTimeout("tcp", host, 8*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Check if TLS is possible by doing a raw TLS peek
	sb.WriteString(colorGreen("  [+] Port reachable\n"))
	// Try HTTP GET with TLS to extract cert info via headers
	cleanHost := strings.TrimSuffix(host, ":443")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://" + cleanHost)
	if err != nil {
		sb.WriteString(colorYellow(fmt.Sprintf("  [TLS] Cannot complete handshake: %v\n", err)))
		return strings.TrimRight(sb.String(), "\n"), nil
	}
	defer resp.Body.Close()
	if resp.TLS != nil {
		sb.WriteString(colorGreen(fmt.Sprintf("  [TLS]  Version    : 0x%04X\n", resp.TLS.Version)))
		for _, cert := range resp.TLS.PeerCertificates {
			sb.WriteString(colorCyan(fmt.Sprintf("  [CERT] Subject    : %s\n", cert.Subject.CommonName)))
			sb.WriteString(colorCyan(fmt.Sprintf("  [CERT] Issuer     : %s\n", cert.Issuer.CommonName)))
			sb.WriteString(colorCyan(fmt.Sprintf("  [CERT] Valid From : %s\n", cert.NotBefore.Format("2006-01-02"))))
			sb.WriteString(colorCyan(fmt.Sprintf("  [CERT] Valid To   : %s\n", cert.NotAfter.Format("2006-01-02"))))
			if len(cert.DNSNames) > 0 {
				sb.WriteString(colorYellow(fmt.Sprintf("  [SAN]  DNS Names  : %s\n", strings.Join(cert.DNSNames, ", "))))
			}
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			if daysLeft < 30 {
				sb.WriteString(colorRed(fmt.Sprintf("  [!]  Certificate expires in %d days!\n", daysLeft)))
			} else {
				sb.WriteString(colorGreen(fmt.Sprintf("  [OK] Days until expiry: %d\n", daysLeft)))
			}
			break
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSaveOutput(filename, content string) (interface{}, error) {
	if err := os.WriteFile(filename, []byte(content+"\n"), 0644); err != nil {
		return nil, err
	}
	return colorGreen("[✓] Saved output → " + filename), nil
}

func (interp *Interpreter) moduleColorPrint(color, text string) (interface{}, error) {
	switch strings.ToLower(color) {
	case "red":
		fmt.Println(colorRed(text))
	case "green":
		fmt.Println(colorGreen(text))
	case "cyan":
		fmt.Println(colorCyan(text))
	case "yellow":
		fmt.Println(colorYellow(text))
	case "magenta":
		fmt.Println(colorMagenta(text))
	case "bold":
		fmt.Println(colorBold(text))
	default:
		fmt.Println(text)
	}
	return nil, nil
}

func (interp *Interpreter) moduleTable(headers, rows interface{}) (interface{}, error) {
	hList, ok := headers.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Table: headers must be a list")
	}
	rList, ok := rows.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Table: rows must be a list of lists")
	}
	// Compute column widths
	cols := len(hList)
	widths := make([]int, cols)
	for i, h := range hList {
		widths[i] = len(toStr(h))
	}
	for _, r := range rList {
		row, ok := r.([]interface{})
		if !ok {
			continue
		}
		for i, cell := range row {
			if i < cols {
				w := len(toStr(cell))
				if w > widths[i] {
					widths[i] = w
				}
			}
		}
	}
	var sb strings.Builder
	// Top border
	sb.WriteString("  ┌")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < cols-1 {
			sb.WriteString("┬")
		}
	}
	sb.WriteString("┐\n")
	// Header row
	sb.WriteString("  │")
	for i, h := range hList {
		cell := toStr(h)
		pad := widths[i] - len(cell)
		sb.WriteString(colorBold(" " + cell + strings.Repeat(" ", pad) + " │"))
	}
	sb.WriteString("\n")
	// Header separator
	sb.WriteString("  ├")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < cols-1 {
			sb.WriteString("┼")
		}
	}
	sb.WriteString("┤\n")
	// Data rows
	for _, r := range rList {
		row, ok := r.([]interface{})
		if !ok {
			continue
		}
		sb.WriteString("  │")
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = toStr(row[i])
			}
			pad := widths[i] - len(cell)
			sb.WriteString(colorCyan(" "+cell) + strings.Repeat(" ", pad+1) + "│")
		}
		sb.WriteString("\n")
	}
	// Bottom border
	sb.WriteString("  └")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < cols-1 {
			sb.WriteString("┴")
		}
	}
	sb.WriteString("┘\n")
	fmt.Print(sb.String())
	return nil, nil
}

func (interp *Interpreter) moduleProgress(label string, total, current int) (interface{}, error) {
	pct := 0
	if total > 0 {
		pct = current * 100 / total
	}
	filled := pct * 30 / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 30-filled)
	fmt.Printf("\r  %s [%s] %d/%d (%d%%)", colorCyan(label), colorGreen(bar), current, total, pct)
	if current >= total {
		fmt.Println()
	}
	return nil, nil
}

func (interp *Interpreter) moduleSpinner(label string, ms int) (interface{}, error) {
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	end := time.Now().Add(time.Duration(ms) * time.Millisecond)
	i := 0
	for time.Now().Before(end) {
		fmt.Printf("\r  %s %s ", colorCyan(frames[i%len(frames)]), label)
		time.Sleep(80 * time.Millisecond)
		i++
	}
	fmt.Printf("\r  %s %s\n", colorGreen("✓"), label)
	return nil, nil
}
