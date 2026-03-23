package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"
)

// ── Build targets ─────────────────────────────────────────────────────────────

type BuildTarget struct {
	OS   string
	Arch string
	Ext  string
	Name string
}

var buildTargets = map[string]BuildTarget{
	"windows":   {OS: "windows", Arch: "amd64", Ext: ".exe", Name: "Windows"},
	"win":       {OS: "windows", Arch: "amd64", Ext: ".exe", Name: "Windows"},
	"linux":     {OS: "linux", Arch: "amd64", Ext: "", Name: "Linux"},
	"mac":       {OS: "darwin", Arch: "amd64", Ext: "", Name: "macOS"},
	"macos":     {OS: "darwin", Arch: "amd64", Ext: "", Name: "macOS"},
	"darwin":    {OS: "darwin", Arch: "amd64", Ext: "", Name: "macOS"},
	"mac-arm":   {OS: "darwin", Arch: "arm64", Ext: "", Name: "macOS (Apple Silicon)"},
	"linux-arm": {OS: "linux", Arch: "arm64", Ext: "", Name: "Linux ARM64"},
}

// ── Build command entry point ─────────────────────────────────────────────────

// RunBuild handles: spectator build <file.str|*> to <output> for <platform>
// Also: spectator build <file.str|*> to <output>  (uses current OS)
func RunBuild(args []string) {
	printBuildBanner()

	// Parse: build <src> to <out> [for <platform>]
	// OR:    build <src> to <out>.<ext>   (infer platform from extension)
	if len(args) < 3 {
		buildHelp()
		return
	}

	srcArg := args[0]
	if strings.ToLower(args[1]) != "to" {
		fmt.Println(colorRed("[!] Syntax: spectator build <file.str|*> to <output> [for windows|linux|mac]"))
		fmt.Println(colorYellow("    Example: spectator build hello.str to hello.exe for windows"))
		return
	}
	outputName := args[2]

	// Determine target platform
	platform := inferCurrentOS()
	if len(args) >= 5 && strings.ToLower(args[3]) == "for" {
		platform = strings.ToLower(args[4])
	} else if len(args) == 4 && strings.ToLower(args[3]) != "for" {
		// "build x.str to output for windows" with missing "for" keyword
		platform = strings.ToLower(args[3])
	} else {
		// Infer from output extension
		if strings.HasSuffix(strings.ToLower(outputName), ".exe") {
			platform = "windows"
		}
	}

	target, ok := buildTargets[platform]
	if !ok {
		fmt.Println(colorRed("[!] Unknown platform: " + platform))
		fmt.Println(colorYellow("    Available: windows, linux, mac, mac-arm, linux-arm"))
		return
	}

	// Collect source files
	srcFiles, err := collectSources(srcArg)
	if err != nil {
		fmt.Println(colorRed("[!] " + err.Error()))
		return
	}

	// Ensure output name has correct extension
	outBase := outputName
	if target.Ext != "" && !strings.HasSuffix(strings.ToLower(outBase), target.Ext) {
		outBase += target.Ext
	}

	fmt.Printf("  %s Building %s → %s (%s)\n", colorCyan("[*]"), strings.Join(srcFiles, ", "), colorGreen(outBase), target.Name)
	fmt.Println(colorCyan("  " + strings.Repeat("─", 55)))

	if err := buildBinary(srcFiles, outBase, target); err != nil {
		fmt.Println(colorRed("[!] Build failed: " + err.Error()))
		return
	}

	// Print success stats
	info, _ := os.Stat(outBase)
	sizeMB := ""
	if info != nil {
		sizeMB = fmt.Sprintf("%.1f MB", float64(info.Size())/(1024*1024))
	}
	fmt.Println(colorGreen("\n  [✓] Build successful!"))
	fmt.Println(colorCyan("      Output   : ") + colorGreen(outBase))
	fmt.Println(colorCyan("      Platform : ") + target.Name + " (" + target.OS + "/" + target.Arch + ")")
	fmt.Println(colorCyan("      Size     : ") + sizeMB)
	fmt.Println(colorCyan("      Sources  : ") + strings.Join(srcFiles, ", "))
	fmt.Println()
	if target.OS != "windows" && runtime.GOOS != "windows" {
		fmt.Println(colorYellow("  Tip: chmod +x " + outBase + " && ./" + outBase))
	}
	fmt.Println()
}

// ── Source file collection ─────────────────────────────────────────────────────

func collectSources(pattern string) ([]string, error) {
	if pattern == "*" {
		matches, err := filepath.Glob("*.str")
		if err != nil || len(matches) == 0 {
			return nil, fmt.Errorf("no .str files found in current directory")
		}
		return matches, nil
	}
	// Glob pattern like "*.str" or single file
	if strings.Contains(pattern, "*") {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			return nil, fmt.Errorf("no files matched pattern: %s", pattern)
		}
		return matches, nil
	}
	// Single file
	if _, err := os.Stat(pattern); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", pattern)
	}
	return []string{pattern}, nil
}

// ── Binary builder ─────────────────────────────────────────────────────────────

func buildBinary(srcFiles []string, outPath string, target BuildTarget) error {
	// Read and merge all source files
	var combined strings.Builder
	combined.WriteString("## Spectator Self-Contained App\n")
	combined.WriteString("## Built: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	combined.WriteString("## Sources: " + strings.Join(srcFiles, ", ") + "\n\n")

	for _, sf := range srcFiles {
		data, err := os.ReadFile(sf)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", sf, err)
		}
		if len(srcFiles) > 1 {
			combined.WriteString("\n## ── " + sf + " ──\n")
		}
		combined.Write(data)
		combined.WriteString("\n")
	}

	// Encode the .str source as base64 to embed in the Go binary
	srcB64 := base64.StdEncoding.EncodeToString([]byte(combined.String()))

	// Find the spectator source directory
	spectatorSrcDir, err := findSpectatorSrc()
	if err != nil {
		return fmt.Errorf("spectator source not found: %w\n  Put your spectator source files in the same directory as the binary, or set SPECTATOR_SRC env var", err)
	}

	fmt.Println(colorCyan("  [*] Spectator source: ") + spectatorSrcDir)
	fmt.Println(colorCyan("  [*] Target: ") + target.Name + " / " + target.Arch)
	fmt.Println(colorCyan("  [*] Generating embedded runner..."))

	// Create a temp build directory
	tmpDir, err := os.MkdirTemp("", "spectator-build-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Copy all spectator source files into tmpDir, skipping main.go (we'll replace it)
	goFiles, err := filepath.Glob(filepath.Join(spectatorSrcDir, "*.go"))
	if err != nil {
		return err
	}

	for _, gf := range goFiles {
		base := filepath.Base(gf)
		if base == "main.go" || base == "build.go" {
			continue
		} // skip — we replace main, skip build
		data, err := os.ReadFile(gf)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmpDir, base), data, 0644); err != nil {
			return err
		}
	}

	// Write go.mod — copy from source dir so dependencies are correct
	srcGoMod, modErr := os.ReadFile(filepath.Join(spectatorSrcDir, "go.mod"))
	if modErr != nil {
		// Fallback: write a basic one with webview2 if GUI
		srcGoMod = []byte("module spectator_app\n\ngo 1.22.2\n\nrequire github.com/jchv/go-webview2 v0.0.0-20221223143126-dc24628cff85\n")
	} else {
		// Replace module name so it builds cleanly
		srcGoMod = []byte(strings.ReplaceAll(string(srcGoMod), "module spectator", "module spectator_app"))
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), srcGoMod, 0644); err != nil {
		return err
	}

	// Copy go.sum if it exists
	if goSum, err := os.ReadFile(filepath.Join(spectatorSrcDir, "go.sum")); err == nil {
		os.WriteFile(filepath.Join(tmpDir, "go.sum"), goSum, 0644)
	}

	// Generate embedded main.go
	embeddedMain, err := generateEmbeddedMain(srcB64, srcFiles)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(embeddedMain), 0644); err != nil {
		return err
	}

	fmt.Println(colorCyan("  [*] Compiling for " + target.Name + "..."))

	// Detect if script uses GUI
	usesGUI := scriptUsesGUI(combined.String())

	// Build flags
	ldflags := "-s -w"
	if target.OS == "windows" && usesGUI {
		// -H windowsgui hides the console window on Windows GUI apps
		ldflags = "-s -w -H windowsgui"
	}

	buildArgs := []string{"build", "-ldflags", ldflags}
	if usesGUI {
		// Include the gui build tag so gui_windows.go is compiled in
		buildArgs = append(buildArgs, "-tags", "gui")
		fmt.Println(colorCyan("  [*] GUI mode detected — building with -tags gui"))
	}
	absOut, _ := filepath.Abs(outPath)
	buildArgs = append(buildArgs, "-o", absOut, ".")

	cmd := exec.Command("go", buildArgs...)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		"GOOS="+target.OS,
		"GOARCH="+target.Arch,
		"CGO_ENABLED=0",
		"GOFLAGS=-mod=mod",
	)
	var stdoutBuf, errBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		errMsg := errBuf.String()
		if errMsg == "" {
			errMsg = stdoutBuf.String()
		}
		return fmt.Errorf("go build error:\n%s", errMsg)
	}

	return nil
}

// scriptUsesGUI returns true if the combined source imports or uses the GUI.
func scriptUsesGUI(src string) bool {
	return strings.Contains(src, "#Import Spec.GUI") ||
		strings.Contains(src, "open.window") ||
		strings.Contains(src, "GUI.label") ||
		strings.Contains(src, "GUI.button")
}

// ── Embedded main template ─────────────────────────────────────────────────────

const embeddedMainTpl = `package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

// Embedded Spectator application
// Sources: {{.Sources}}
// Built:   {{.BuildTime}}

const _embeddedSrc = ` + "`{{.SourceB64}}`" + `

func main() {
	// Decode the embedded source
	srcBytes, err := base64.StdEncoding.DecodeString(_embeddedSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Fatal: corrupted embedded source: %v\n", err)
		os.Exit(1)
	}

	lexer := NewLexer(string(srcBytes))
	tokens, err := lexer.Tokenize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Lex error: %v\n", err)
		os.Exit(1)
	}
	parser := NewParser(tokens)
	prog, err := parser.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Parse error: %v\n", err)
		os.Exit(1)
	}
	interp := NewInterpreter()
	if err := interp.Run(prog); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Runtime error: %v\n", err)
		os.Exit(1)
	}
}

// Stub rawReader so we don't need main.go helpers
type rawReader struct{ r *os.File }
func (b *rawReader) ReadString(delim byte) (string, error) {
	var result []byte; buf := make([]byte, 1)
	for {
		n, err := b.r.Read(buf)
		if n > 0 { result = append(result, buf[0]); if buf[0] == delim { return string(result), nil } }
		if err != nil { return string(result), err }
	}
}
`

func generateEmbeddedMain(srcB64 string, srcFiles []string) (string, error) {
	type tmplData struct {
		SourceB64 string
		Sources   string
		BuildTime string
	}

	tpl, err := template.New("main").Parse(embeddedMainTpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	tpl.Execute(&buf, tmplData{ //nolint:errcheck
		SourceB64: srcB64,
		Sources:   strings.Join(srcFiles, ", "),
		BuildTime: time.Now().Format("2006-01-02 15:04:05"),
	})

	// Try to gofmt the output (best effort)
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return buf.String(), nil
	}
	return string(formatted), nil
}

// ── Find spectator source directory ───────────────────────────────────────────

func findSpectatorSrc() (string, error) {
	// 1. SPECTATOR_SRC env var
	if env := os.Getenv("SPECTATOR_SRC"); env != "" {
		if _, err := os.Stat(filepath.Join(env, "interpreter.go")); err == nil {
			return env, nil
		}
	}
	// 2. Same dir as the running binary
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(dir, "interpreter.go")); err == nil {
			return dir, nil
		}
	}
	// 3. Current working directory
	if _, err := os.Stat("interpreter.go"); err == nil {
		return ".", nil
	}
	// 4. Walk up from cwd looking for go.mod + interpreter.go
	cwd, _ := os.Getwd()
	for d := cwd; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "interpreter.go")); err == nil {
			return d, nil
		}
	}
	return "", fmt.Errorf("cannot find spectator source (interpreter.go)")
}

// ── Cross-compile batch ────────────────────────────────────────────────────────

// RunBuildAll builds for all three major platforms at once:
// spectator build * to myapp for all
func runBuildAll(srcArg, baseName string) {
	platforms := []string{"windows", "linux", "mac"}
	outputs := []string{baseName + ".exe", baseName, baseName + "-mac"}
	fmt.Println(colorBold("\n  [*] Building for all platforms...\n"))
	for i, plat := range platforms {
		args := []string{srcArg, "to", outputs[i], "for", plat}
		fmt.Printf("  %s %-8s → %s\n", colorCyan("[~]"), plat, outputs[i])
		RunBuild(args)
	}
}

// ── zipSources: pack .str files into a distributable zip ─────────────────────

func RunPack(args []string) {
	// spectator pack *.str to archive.zip
	if len(args) < 3 || strings.ToLower(args[1]) != "to" {
		fmt.Println(colorRed("[!] Usage: spectator pack <*.str|*> to <archive.zip>"))
		return
	}
	srcArg, outZip := args[0], args[2]
	if !strings.HasSuffix(outZip, ".zip") {
		outZip += ".zip"
	}

	srcFiles, err := collectSources(srcArg)
	if err != nil {
		fmt.Println(colorRed("[!] " + err.Error()))
		return
	}

	zf, err := os.Create(outZip)
	if err != nil {
		fmt.Println(colorRed("[!] " + err.Error()))
		return
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()
	for _, sf := range srcFiles {
		data, err := os.ReadFile(sf)
		if err != nil {
			fmt.Println(colorYellow("  [~] Skip: " + sf))
			continue
		}
		w, err := zw.Create(filepath.Base(sf))
		if err != nil {
			continue
		}
		w.Write(data) //nolint:errcheck
		fmt.Println(colorGreen("  [+] ") + sf)
	}
	fmt.Println(colorGreen("\n  [✓] Packed → " + outZip + "\n"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func inferCurrentOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "mac"
	default:
		return "linux"
	}
}

func printBuildBanner() {
	fmt.Println(colorCyan("\n  ╔══════════════════════════════════════════╗"))
	fmt.Println(colorCyan("    ║        SPECTATOR BUILD SYSTEM  v1.0      ║"))
	fmt.Println(colorCyan("    ╚══════════════════════════════════════════╝\n"))
}

func buildHelp() {
	fmt.Println(colorBold("  Build Usage:"))
	cmds := [][2]string{
		{"spectator build hello.str to hello for windows", "Build Windows .exe"},
		{"spectator build hello.str to hello for linux", "Build Linux binary"},
		{"spectator build hello.str to hello for mac", "Build macOS binary"},
		{"spectator build hello.str to hello for mac-arm", "Build macOS Apple Silicon"},
		{"spectator build hello.str to hello for linux-arm", "Build Linux ARM64"},
		{"spectator build * to mytool for linux", "Bundle ALL .str files"},
		{"spectator pack * to myproject.zip", "Pack sources into zip"},
	}
	for _, c := range cmds {
		fmt.Printf("  \033[33m%-50s\033[0m %s\n", c[0], c[1])
	}
	fmt.Println()
	fmt.Println(colorBold("  Platform aliases:"))
	fmt.Println(colorCyan("  windows / win  →  Windows x64 (.exe)"))
	fmt.Println(colorCyan("  linux          →  Linux x64"))
	fmt.Println(colorCyan("  mac / macos    →  macOS x64"))
	fmt.Println(colorCyan("  mac-arm        →  macOS Apple Silicon (M1/M2/M3)"))
	fmt.Println(colorCyan("  linux-arm      →  Linux ARM64 (Raspberry Pi, etc.)"))
	fmt.Println()
	fmt.Println(colorBold("  Requirements:"))
	fmt.Println(colorYellow("  • Go 1.18+ must be installed on your system"))
	fmt.Println(colorYellow("  • Spectator .go source files must be alongside the binary"))
	fmt.Println(colorYellow("  • Set SPECTATOR_SRC=/path/to/source if needed"))
	fmt.Println()
}
