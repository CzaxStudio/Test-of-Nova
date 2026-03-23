package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// ── Runner execution engine ───────────────────────────────────────────────────
//
// Syntax recap:
//   # runner<?cmd args {var}>          live passthrough (stdout/stderr → terminal)
//   result = # runner<?cmd>            capture stdout into variable
//   # runner<?cmd> | # runner<?cmd2>   pipe stdout of cmd into stdin of cmd2
//   # runner<?cmd> {                   feed lines as stdin to cmd
//       "payload"
//       varname
//   }
//   # runner<?cmd {host} -p {port}>    variable interpolation in command string

// execRunner is the main entry point called from the interpreter for RunnerStmt.
func (interp *Interpreter) execRunner(s *RunnerStmt, env *Env) error {
	if s.PipeTo != nil {
		return interp.execRunnerPipeline(s, env)
	}

	// Interpolate variables in the command string
	cmd, err := interp.interpolateCommand(s.RawCmd, env)
	if err != nil {
		return err
	}

	// Build stdin data from optional body block
	var stdinBuf bytes.Buffer
	for _, inp := range s.Stdin {
		v, err := interp.evalExpr(inp, env)
		if err != nil {
			return err
		}
		stdinBuf.WriteString(toStr(v) + "\n")
	}

	// Capture mode: store output in variable
	if s.CaptureVar != "" {
		out, err := runCaptured(cmd, stdinBuf.Bytes())
		if err != nil {
			env.Set(s.CaptureVar, "")
			return fmt.Errorf("runner error: %v", err)
		}
		env.Set(s.CaptureVar, out)
		return nil
	}

	// Silent mode
	if s.Mode == "silent" {
		runCaptured(cmd, stdinBuf.Bytes()) //nolint:errcheck
		return nil
	}

	// Live passthrough mode: inherit terminal
	return runLive(cmd, stdinBuf.Bytes())
}

// evalRunnerExpr is called when runner appears as an expression (capture mode).
func (interp *Interpreter) evalRunnerExpr(e *RunnerExpr, env *Env) (interface{}, error) {
	// Build the full pipeline as a single shell command joined with ' | '
	// This is the most correct approach since the OS shell handles piping natively.
	stages := collectRunnerExprStages(e)
	parts := make([]string, len(stages))
	for i, stage := range stages {
		cmd, err := interp.interpolateCommand(stage.RawCmd, env)
		if err != nil {
			return nil, err
		}
		parts[i] = cmd
	}
	fullCmd := strings.Join(parts, " | ")
	out, _ := runCaptured(fullCmd, nil)
	return strings.TrimRight(out, "\r\n"), nil
}

// execRunnerPipeline: # runner<?a> | # runner<?b>
// Joins all pipeline stages with shell ' | ' and runs as one sh -c command.
// This gives us full shell pipeline support including grep, awk, sed, etc.
func (interp *Interpreter) execRunnerPipeline(s *RunnerStmt, env *Env) error {
	stages := collectRunnerStages(s)
	parts := make([]string, len(stages))
	for i, stage := range stages {
		cmd, err := interp.interpolateCommand(stage.RawCmd, env)
		if err != nil {
			return err
		}
		parts[i] = cmd
	}
	fullCmd := strings.Join(parts, " | ")

	// Build stdin from first stage body if present
	var stdinBuf bytes.Buffer
	if len(stages[0].Stdin) > 0 {
		for _, inp := range stages[0].Stdin {
			v, _ := interp.evalExpr(inp, env)
			stdinBuf.WriteString(toStr(v) + "\n")
		}
	}
	printRunnerHeader(fullCmd)
	return runLive(fullCmd, stdinBuf.Bytes())
}

// evalRunnerPipelineExpr is now handled directly in evalRunnerExpr above.
func (interp *Interpreter) evalRunnerPipelineExpr(e *RunnerExpr, env *Env) (interface{}, error) {
	return interp.evalRunnerExpr(e, env)
}

// ── Core execution helpers ────────────────────────────────────────────────────

// runLive runs a command with inherited stdin/stdout/stderr (full terminal passthrough).
// This means interactive apps like vim, python REPL, ssh work correctly.
func runLive(rawCmd string, stdinData []byte) error {
	c, err := buildCmd(rawCmd)
	if err != nil {
		return err
	}

	if len(stdinData) > 0 {
		c.Stdin = bytes.NewReader(stdinData)
	} else {
		c.Stdin = os.Stdin
	}
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	printRunnerHeader(rawCmd)
	if err := c.Run(); err != nil {
		// Non-zero exit is not a fatal Spectator error — just report it
		fmt.Println(colorYellow(fmt.Sprintf("  [runner] exited: %v", err)))
	}
	return nil
}

// runCaptured runs a command and returns its combined stdout+stderr as a string.
func runCaptured(rawCmd string, stdinData []byte) (string, error) {
	c, err := buildCmd(rawCmd)
	if err != nil {
		return "", err
	}

	if len(stdinData) > 0 {
		c.Stdin = bytes.NewReader(stdinData)
	}

	var outBuf bytes.Buffer
	c.Stdout = &outBuf
	c.Stderr = &outBuf

	c.Run() //nolint:errcheck  — we return output regardless of exit code
	return outBuf.String(), nil
}

// buildCmd constructs an exec.Cmd from a raw command string,
// using the OS shell so quoting, wildcards, env vars all work naturally.
func buildCmd(rawCmd string) (*exec.Cmd, error) {
	rawCmd = strings.TrimSpace(rawCmd)
	if rawCmd == "" {
		return nil, fmt.Errorf("empty command")
	}

	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", rawCmd)
	} else {
		c = exec.Command("sh", "-c", rawCmd)
	}
	return c, nil
}

// ── Variable interpolation ────────────────────────────────────────────────────

// interpolateCommand replaces {varname} placeholders in the command template
// with values from the Spectator environment.
//
// Examples:
//
//	"nmap -sV {target}"        → "nmap -sV 192.168.1.1"
//	"python3 {script} {port}"  → "python3 exploit.py 8080"
//	"curl {url}"               → "curl http://example.com"
func (interp *Interpreter) interpolateCommand(template string, env *Env) (string, error) {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	var lastErr error
	result := re.ReplaceAllStringFunc(template, func(match string) string {
		varName := match[1 : len(match)-1] // strip { }
		varName = strings.TrimSpace(varName)
		val, ok := env.Get(varName)
		if !ok {
			lastErr = fmt.Errorf("runner: undefined variable %q in command template", varName)
			return match // leave as-is
		}
		return toStr(val)
	})
	return result, lastErr
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func collectRunnerStages(s *RunnerStmt) []*RunnerStmt {
	stages := []*RunnerStmt{s}
	cur := s.PipeTo
	for cur != nil {
		stages = append(stages, cur)
		cur = cur.PipeTo
	}
	return stages
}

func collectRunnerExprStages(e *RunnerExpr) []*RunnerExpr {
	stages := []*RunnerExpr{e}
	cur := e.PipeTo
	for cur != nil {
		stages = append(stages, cur)
		cur = cur.PipeTo
	}
	return stages
}

func printRunnerHeader(cmd string) {
	// Truncate long commands for display
	display := cmd
	if len(display) > 72 {
		display = display[:69] + "..."
	}
	fmt.Println(colorCyan("[runner] ") + colorBold(display))
}

// streamLines reads from r and writes each line to w with an optional prefix,
// used for live output coloring.
func streamLines(r io.Reader, w io.Writer, prefix string) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			lines := strings.Split(string(buf[:n]), "\n")
			for _, line := range lines {
				if line != "" {
					fmt.Fprintln(w, prefix+line)
				}
			}
		}
		if err != nil {
			break
		}
	}
}
