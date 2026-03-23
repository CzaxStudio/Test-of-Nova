//go:build windows && !gui
// +build windows,!gui

package main

import "fmt"

// GUI stub for Windows builds without the gui tag.
// To enable GUI: go build -tags gui -o Spectator.exe .

func (interp *Interpreter) guiBuiltin(name string, args []interface{}, argExprs []Expr, env *Env) (interface{}, error) {
	return nil, fmt.Errorf("GUI requires rebuilding with: go build -tags gui -o Spectator.exe .")
}
