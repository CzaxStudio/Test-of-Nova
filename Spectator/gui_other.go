//go:build !windows
// +build !windows

package main

import "fmt"

func (interp *Interpreter) guiBuiltin(name string, args []interface{}, argExprs []Expr, env *Env) (interface{}, error) {
	return nil, fmt.Errorf("GUI is Windows-only in this build")
}
