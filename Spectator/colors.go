package main

// colors.go — ANSI terminal color helpers shared across all files.
// Kept in its own file so space.go, build.go, main.go, and interpreter.go
// can all use them without any cross-file dependency issues.

func colorBold(s string) string    { return "\033[1m" + s + "\033[0m" }
func colorGreen(s string) string   { return "\033[32m" + s + "\033[0m" }
func colorRed(s string) string     { return "\033[31m" + s + "\033[0m" }
func colorCyan(s string) string    { return "\033[36m" + s + "\033[0m" }
func colorYellow(s string) string  { return "\033[33m" + s + "\033[0m" }
func colorMagenta(s string) string { return "\033[35m" + s + "\033[0m" }
func colorWhite(s string) string   { return "\033[97m" + s + "\033[0m" }
func colorDim(s string) string     { return "\033[2m" + s + "\033[0m" }
