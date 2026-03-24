package main

// ── Spectator TUI — Pure-Go Terminal UI Engine ────────────────────────────────
//
// Zero external dependencies. Uses raw ANSI/VT100 escape codes.
// Works on Windows Terminal, PowerShell, CMD (Win10+), Linux, macOS.
//
// New builtins added to Spectator:
//
//   TUI.window(title)              → create a full-screen TUI window
//   TUI.header(win, text)          → set the top header bar text
//   TUI.footer(win, text)          → set the bottom status bar text
//   TUI.panel(win, x,y,w,h, title) → add a bordered panel at position
//   TUI.text(win, x,y, text)       → print text at position
//   TUI.table(win, x,y,w, headers, rows) → draw a table
//   TUI.bar(win, x,y,w, pct, color) → draw a progress/stat bar
//   TUI.badge(win, x,y, text, color) → colored badge/pill
//   TUI.input(win, x,y,w, label)   → input field → returns string
//   TUI.confirm(win, msg)          → yes/no prompt → returns bool
//   TUI.menu(win, title, items)    → arrow-key menu → returns chosen item
//   TUI.clear(win)                 → clear the window
//   TUI.refresh(win)               → redraw everything
//   TUI.close(win)                 → restore terminal and exit TUI mode
//   TUI.alert(win, msg, color)     → popup alert box
//   TUI.width()                    → terminal width
//   TUI.height()                   → terminal height
//   TUI.run(win, func)             → run a TUI app with an update loop
//
// Usage in .str:
//   win = TUI.window("Spectator Scanner")
//   TUI.header(win, " SPECTATOR v2.0  |  Recon Dashboard")
//   TUI.panel(win, 1,3,40,20, "Targets")
//   TUI.text(win, 3,5, "Enter target below:")
//   target = TUI.input(win, 3,7,35, "Target: ")
//   TUI.close(win)

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// ── TUI state ─────────────────────────────────────────────────────────────────

type TUIWindow struct {
	Title   string
	Width   int
	Height  int
	Header  string
	Footer  string
	widgets []tuiWidget
}

type tuiWidget struct {
	kind string
	x, y int
	data interface{}
}

var tuiWindows = map[string]*TUIWindow{}
var tuiWinCount = 0

// ── ANSI escape sequences ─────────────────────────────────────────────────────

const (
	tuiReset   = "\033[0m"
	tuiBold    = "\033[1m"
	tuiDim     = "\033[2m"
	tuiReverse = "\033[7m"

	// Foreground colors
	tuiFgBlack   = "\033[30m"
	tuiFgRed     = "\033[31m"
	tuiFgGreen   = "\033[32m"
	tuiFgYellow  = "\033[33m"
	tuiFgBlue    = "\033[34m"
	tuiFgMagenta = "\033[35m"
	tuiFgCyan    = "\033[36m"
	tuiFgWhite   = "\033[37m"
	tuiFgDefault = "\033[39m"

	// Bright foreground
	tuiFgBrightRed     = "\033[91m"
	tuiFgBrightGreen   = "\033[92m"
	tuiFgBrightYellow  = "\033[93m"
	tuiFgBrightBlue    = "\033[94m"
	tuiFgBrightMagenta = "\033[95m"
	tuiFgBrightCyan    = "\033[96m"
	tuiFgBrightWhite   = "\033[97m"

	// Background colors
	tuiBgBlack   = "\033[40m"
	tuiBgRed     = "\033[41m"
	tuiBgGreen   = "\033[42m"
	tuiBgYellow  = "\033[43m"
	tuiBgBlue    = "\033[44m"
	tuiBgMagenta = "\033[45m"
	tuiBgCyan    = "\033[46m"
	tuiBgWhite   = "\033[47m"
	tuiBgDefault = "\033[49m"

	// Dark background colors (256-color)
	tuiBgDark   = "\033[48;5;235m"
	tuiBgPanel  = "\033[48;5;234m"
	tuiBgHeader = "\033[48;5;17m"

	// Cursor control
	tuiHideCursor  = "\033[?25l"
	tuiShowCursor  = "\033[?25h"
	tuiClearScreen = "\033[2J"
	tuiHome        = "\033[H"
	tuiAltBuf      = "\033[?1049h" // enter alternate screen buffer
	tuiNormBuf     = "\033[?1049l" // leave alternate screen buffer
)

func tuiMoveTo(x, y int) string { return fmt.Sprintf("\033[%d;%dH", y, x) }
func tuiColor(name string) string {
	switch strings.ToLower(name) {
	case "red":
		return tuiFgBrightRed
	case "green":
		return tuiFgBrightGreen
	case "yellow":
		return tuiFgBrightYellow
	case "blue":
		return tuiFgBrightBlue
	case "magenta":
		return tuiFgBrightMagenta
	case "cyan":
		return tuiFgBrightCyan
	case "white":
		return tuiFgBrightWhite
	case "dim":
		return tuiDim
	case "bold":
		return tuiBold
	case "critical":
		return tuiFgBrightRed
	case "high":
		return tuiFgYellow
	case "medium":
		return tuiFgBrightYellow
	case "low":
		return tuiFgBrightBlue
	case "info":
		return tuiFgBrightGreen
	}
	return tuiFgWhite
}

// ── Terminal size detection ───────────────────────────────────────────────────

func tuiGetSize() (int, int) {
	// Try TIOCGWINSZ via environment first (works in most cases)
	cols, rows := 120, 35 // safe defaults
	// On most systems we can query via escape sequence
	// Using COLUMNS/LINES env as fallback
	if c := os.Getenv("COLUMNS"); c != "" {
		fmt.Sscan(c, &cols)
	}
	if r := os.Getenv("LINES"); r != "" {
		fmt.Sscan(r, &rows)
	}
	return cols, rows
}

// ── Box drawing characters ────────────────────────────────────────────────────

const (
	boxTL = "╔"
	boxTR = "╗"
	boxBL = "╚"
	boxBR = "╝"
	boxH  = "═"
	boxV  = "║"
	boxML = "╠"
	boxMR = "╣"
	boxMT = "╦"
	boxMB = "╩"
	boxMX = "╬"
	// Thin box
	tboxTL = "┌"
	tboxTR = "┐"
	tboxBL = "└"
	tboxBR = "┘"
	tboxH  = "─"
	tboxV  = "│"
)

func tuiHLine(w int, ch string) string { return strings.Repeat(ch, w) }
func tuiPadR(s string, w int) string {
	l := utf8.RuneCountInString(s)
	if l >= w {
		return string([]rune(s)[:w])
	}
	return s + strings.Repeat(" ", w-l)
}
func tuiCenter(s string, w int) string {
	l := utf8.RuneCountInString(s)
	if l >= w {
		return s[:w]
	}
	pad := (w - l) / 2
	return strings.Repeat(" ", pad) + s + strings.Repeat(" ", w-l-pad)
}

// ── TUI builtin dispatcher ────────────────────────────────────────────────────

func (interp *Interpreter) tuiBuiltin(name string, args []interface{}) (interface{}, error) {
	switch name {

	// ── TUI.window(title) → win_id ──────────────────────────────────────────
	case "tuiWindow":
		title := "Spectator"
		if len(args) >= 1 {
			title = toStr(args[0])
		}
		w, h := tuiGetSize()
		tuiWinCount++
		id := fmt.Sprintf("tui_%d", tuiWinCount)
		win := &TUIWindow{
			Title:  title,
			Width:  w,
			Height: h,
			Header: " " + title,
			Footer: " Space=Select  Q=Quit  Tab=Next  Arrow=Navigate",
		}
		tuiWindows[id] = win
		// Enter alternate screen, hide cursor, clear
		fmt.Print(tuiAltBuf + tuiHideCursor + tuiClearScreen + tuiHome)
		tuiRenderChrome(win)
		return id, nil

	// ── TUI.header(win, text) ───────────────────────────────────────────────
	case "tuiHeader":
		if len(args) < 2 {
			return nil, nil
		}
		win := tuiGetWin(toStr(args[0]))
		if win == nil {
			return nil, nil
		}
		win.Header = toStr(args[1])
		tuiDrawHeader(win)
		return nil, nil

	// ── TUI.footer(win, text) ───────────────────────────────────────────────
	case "tuiFooter":
		if len(args) < 2 {
			return nil, nil
		}
		win := tuiGetWin(toStr(args[0]))
		if win == nil {
			return nil, nil
		}
		win.Footer = toStr(args[1])
		tuiDrawFooter(win)
		return nil, nil

	// ── TUI.panel(win, x,y,w,h, title) ─────────────────────────────────────
	case "tuiPanel":
		if len(args) < 6 {
			return nil, fmt.Errorf("TUI.panel requires win,x,y,w,h,title")
		}
		win := tuiGetWin(toStr(args[0]))
		if win == nil {
			return nil, nil
		}
		x, y, pw, ph := int(toFloat(args[1])), int(toFloat(args[2])), int(toFloat(args[3])), int(toFloat(args[4]))
		title := toStr(args[5])
		tuiDrawPanel(x, y, pw, ph, title, false)
		return nil, nil

	// ── TUI.text(win, x,y, text, color?) ────────────────────────────────────
	case "tuiText":
		if len(args) < 4 {
			return nil, fmt.Errorf("TUI.text requires win,x,y,text")
		}
		x, y := int(toFloat(args[1])), int(toFloat(args[2]))
		text := toStr(args[3])
		clr := tuiFgWhite
		if len(args) >= 5 {
			clr = tuiColor(toStr(args[4]))
		}
		fmt.Print(tuiMoveTo(x, y) + clr + text + tuiReset)
		return nil, nil

	// ── TUI.clear(win) ───────────────────────────────────────────────────────
	case "tuiClear":
		fmt.Print(tuiClearScreen + tuiHome)
		if len(args) >= 1 {
			if win := tuiGetWin(toStr(args[0])); win != nil {
				tuiRenderChrome(win)
			}
		}
		return nil, nil

	// ── TUI.refresh(win) ────────────────────────────────────────────────────
	case "tuiRefresh":
		if len(args) >= 1 {
			if win := tuiGetWin(toStr(args[0])); win != nil {
				tuiRenderChrome(win)
			}
		}
		return nil, nil

	// ── TUI.close(win) ───────────────────────────────────────────────────────
	case "tuiClose":
		fmt.Print(tuiShowCursor + tuiNormBuf + tuiReset)
		if len(args) >= 1 {
			delete(tuiWindows, toStr(args[0]))
		}
		return nil, nil

	// ── TUI.table(win, x,y,w, headers, rows) ────────────────────────────────
	case "tuiTable":
		if len(args) < 6 {
			return nil, fmt.Errorf("TUI.table requires win,x,y,w,headers,rows")
		}
		x, y, tw := int(toFloat(args[1])), int(toFloat(args[2])), int(toFloat(args[3]))
		headers, ok1 := args[4].([]interface{})
		rows, ok2 := args[5].([]interface{})
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("TUI.table: headers and rows must be lists")
		}
		tuiDrawTable(x, y, tw, headers, rows)
		return nil, nil

	// ── TUI.bar(win, x,y,w, pct, color?) ───────────────────────────────────
	case "tuiBar":
		if len(args) < 5 {
			return nil, fmt.Errorf("TUI.bar requires win,x,y,w,pct")
		}
		x, y, bw := int(toFloat(args[1])), int(toFloat(args[2])), int(toFloat(args[3]))
		pct := toFloat(args[4])
		if pct > 100 {
			pct = 100
		}
		if pct < 0 {
			pct = 0
		}
		clr := tuiFgBrightCyan
		if len(args) >= 6 {
			clr = tuiColor(toStr(args[5]))
		}
		tuiDrawBar(x, y, bw, pct, clr)
		return nil, nil

	// ── TUI.badge(win, x,y, text, color?) ──────────────────────────────────
	case "tuiBadge":
		if len(args) < 4 {
			return nil, fmt.Errorf("TUI.badge requires win,x,y,text")
		}
		x, y := int(toFloat(args[1])), int(toFloat(args[2]))
		text := toStr(args[3])
		clr := tuiFgBrightCyan
		if len(args) >= 5 {
			clr = tuiColor(toStr(args[4]))
		}
		fmt.Print(tuiMoveTo(x, y) + tuiReverse + clr + " " + text + " " + tuiReset)
		return nil, nil

	// ── TUI.input(win, x,y,w, label) → string ──────────────────────────────
	case "tuiInput":
		if len(args) < 5 {
			return nil, fmt.Errorf("TUI.input requires win,x,y,w,label")
		}
		x, y, iw := int(toFloat(args[1])), int(toFloat(args[2])), int(toFloat(args[3]))
		label := toStr(args[4])
		return tuiReadInput(x, y, iw, label), nil

	// ── TUI.confirm(win, msg) → bool ───────────────────────────────────────
	case "tuiConfirm":
		if len(args) < 2 {
			return false, nil
		}
		win := tuiGetWin(toStr(args[0]))
		msg := toStr(args[1])
		return tuiShowConfirm(win, msg), nil

	// ── TUI.menu(win, title, items) → string ───────────────────────────────
	case "tuiMenu":
		if len(args) < 3 {
			return nil, fmt.Errorf("TUI.menu requires win,title,items")
		}
		win := tuiGetWin(toStr(args[0]))
		title := toStr(args[1])
		items, ok := args[2].([]interface{})
		if !ok {
			return nil, fmt.Errorf("TUI.menu: items must be a list")
		}
		return tuiShowMenu(win, title, items), nil

	// ── TUI.alert(win, msg, color?) ─────────────────────────────────────────
	case "tuiAlert":
		if len(args) < 2 {
			return nil, nil
		}
		win := tuiGetWin(toStr(args[0]))
		msg := toStr(args[1])
		clr := "cyan"
		if len(args) >= 3 {
			clr = toStr(args[2])
		}
		tuiShowAlert(win, msg, clr)
		return nil, nil

	// ── TUI.width() / TUI.height() ──────────────────────────────────────────
	case "tuiWidth":
		w, _ := tuiGetSize()
		return float64(w), nil
	case "tuiHeight":
		_, h := tuiGetSize()
		return float64(h), nil

	// ── TUI.print(win, text) — appends to scrollable log area ───────────────
	case "tuiPrint":
		if len(args) < 2 {
			return nil, nil
		}
		text := toStr(args[1])
		// Print to current cursor position
		fmt.Println(text)
		return nil, nil
	}
	return nil, fmt.Errorf("unknown TUI function: %q", name)
}

// ── Chrome rendering (header + footer) ───────────────────────────────────────

func tuiRenderChrome(win *TUIWindow) {
	tuiDrawHeader(win)
	tuiDrawFooter(win)
}

func tuiDrawHeader(win *TUIWindow) {
	w := win.Width
	text := tuiPadR(" ◈  "+win.Header, w)
	fmt.Print(tuiMoveTo(1, 1) + tuiBgHeader + tuiFgBrightCyan + tuiBold + text + tuiReset)
}

func tuiDrawFooter(win *TUIWindow) {
	w, h := tuiGetSize()
	win.Width = w
	win.Height = h
	text := tuiPadR(" "+win.Footer, w)
	fmt.Print(tuiMoveTo(1, h) + tuiBgDark + tuiDim + text + tuiReset)
}

// ── Panel drawing ─────────────────────────────────────────────────────────────

func tuiDrawPanel(x, y, w, h int, title string, active bool) {
	tl, tr, bl, br, hc, vc := tboxTL, tboxTR, tboxBL, tboxBR, tboxH, tboxV
	if active {
		tl, tr, bl, br, hc, vc = boxTL, boxTR, boxBL, boxBR, boxH, boxV
	}

	clr := tuiDim + tuiFgCyan
	if active {
		clr = tuiFgBrightCyan
	}

	inner := w - 2
	// Top border with title
	titleStr := ""
	if title != "" {
		t := " " + title + " "
		if utf8.RuneCountInString(t) > inner-2 {
			t = t[:inner-2]
		}
		rest := inner - utf8.RuneCountInString(t)
		titleStr = tuiHLine(rest/2, hc) + tuiFgBrightWhite + tuiBold + t + tuiReset + clr + tuiHLine(inner-rest/2-utf8.RuneCountInString(t), hc)
	} else {
		titleStr = tuiHLine(inner, hc)
	}

	fmt.Print(tuiMoveTo(x, y) + clr + tl + titleStr + tr + tuiReset)

	// Side borders
	for i := 1; i < h-1; i++ {
		fmt.Print(tuiMoveTo(x, y+i) + clr + vc + tuiReset)
		fmt.Print(tuiMoveTo(x+w-1, y+i) + clr + vc + tuiReset)
	}

	// Bottom border
	fmt.Print(tuiMoveTo(x, y+h-1) + clr + bl + tuiHLine(inner, hc) + br + tuiReset)
}

// ── Table drawing ─────────────────────────────────────────────────────────────

func tuiDrawTable(x, y, tw int, headers, rows []interface{}) {
	n := len(headers)
	if n == 0 {
		return
	}

	// Calculate column widths
	colW := make([]int, n)
	for i, h := range headers {
		if l := utf8.RuneCountInString(toStr(h)); l > colW[i] {
			colW[i] = l
		}
	}
	for _, row := range rows {
		if rl, ok := row.([]interface{}); ok {
			for i := 0; i < n && i < len(rl); i++ {
				if l := utf8.RuneCountInString(toStr(rl[i])); l > colW[i] {
					colW[i] = l
				}
			}
		}
	}

	// Cap total width
	total := n + 1
	for _, w := range colW {
		total += w + 2
	}
	if total > tw {
		extra := total - tw
		colW[n-1] -= extra
		if colW[n-1] < 4 {
			colW[n-1] = 4
		}
	}

	sep := func(yy int) {
		fmt.Print(tuiMoveTo(x, yy) + tuiFgCyan)
		row := tboxTL
		for i, w := range colW {
			row += tuiHLine(w+2, tboxH)
			if i < n-1 {
				row += "┬"
			} else {
				row += tboxTR
			}
		}
		fmt.Print(row + tuiReset)
	}
	midSep := func(yy int) {
		fmt.Print(tuiMoveTo(x, yy) + tuiFgCyan)
		row := "├"
		for i, w := range colW {
			row += tuiHLine(w+2, tboxH)
			if i < n-1 {
				row += "┼"
			} else {
				row += "┤"
			}
		}
		fmt.Print(row + tuiReset)
	}
	botSep := func(yy int) {
		fmt.Print(tuiMoveTo(x, yy) + tuiFgCyan)
		row := tboxBL
		for i, w := range colW {
			row += tuiHLine(w+2, tboxH)
			if i < n-1 {
				row += "┴"
			} else {
				row += tboxBR
			}
		}
		fmt.Print(row + tuiReset)
	}
	printRow := func(cells []interface{}, yy int, isHeader bool) {
		fmt.Print(tuiMoveTo(x, yy) + tuiFgCyan + tboxV + tuiReset)
		for i, w := range colW {
			cell := ""
			if i < len(cells) {
				cell = toStr(cells[i])
			}
			if isHeader {
				fmt.Print(" " + tuiBold + tuiFgBrightCyan + tuiPadR(cell, w) + tuiReset + " ")
			} else {
				// Color cells by content
				clr := tuiCellColor(cell)
				fmt.Print(" " + clr + tuiPadR(cell, w) + tuiReset + " ")
			}
			fmt.Print(tuiFgCyan + tboxV + tuiReset)
		}
	}

	cur := y
	sep(cur)
	cur++
	printRow(headers, cur, true)
	cur++
	midSep(cur)
	cur++
	for _, row := range rows {
		rl, _ := row.([]interface{})
		printRow(rl, cur, false)
		cur++
	}
	botSep(cur)
}

func tuiCellColor(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return tuiFgBrightRed + tuiBold
	case "HIGH":
		return tuiFgYellow + tuiBold
	case "MEDIUM":
		return tuiFgBrightYellow
	case "LOW":
		return tuiFgBrightBlue
	case "INFO":
		return tuiFgBrightGreen
	case "OPEN":
		return tuiFgBrightGreen
	case "CLOSED":
		return tuiFgBrightRed
	case "FILTERED":
		return tuiFgYellow
	case "UP":
		return tuiFgBrightGreen
	case "DOWN":
		return tuiFgBrightRed
	}
	return tuiFgWhite
}

// ── Bar drawing ───────────────────────────────────────────────────────────────

func tuiDrawBar(x, y, w int, pct float64, clr string) {
	filled := int(float64(w) * pct / 100)
	empty := w - filled
	bar := clr + strings.Repeat("█", filled) + tuiDim + strings.Repeat("░", empty) + tuiReset
	pctStr := fmt.Sprintf(" %3.0f%%", pct)
	fmt.Print(tuiMoveTo(x, y) + bar + tuiFgWhite + pctStr)
}

// ── Input reading ─────────────────────────────────────────────────────────────

func tuiReadInput(x, y, w int, label string) string {
	fmt.Print(tuiShowCursor)
	defer fmt.Print(tuiHideCursor)

	labelW := utf8.RuneCountInString(label)
	inputX := x + labelW
	inputW := w - labelW

	// Draw label
	fmt.Print(tuiMoveTo(x, y) + tuiFgBrightCyan + tuiBold + label + tuiReset)
	// Draw input field background
	fmt.Print(tuiMoveTo(inputX, y) + tuiBgDark + strings.Repeat(" ", inputW) + tuiReset)
	fmt.Print(tuiMoveTo(inputX, y))

	// Read line
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimRight(input, "\r\n")
}

// ── Confirm dialog ────────────────────────────────────────────────────────────

func tuiShowConfirm(win *TUIWindow, msg string) bool {
	w, h := tuiGetSize()
	dw := utf8.RuneCountInString(msg) + 10
	if dw < 40 {
		dw = 40
	}
	dh := 7
	dx := (w - dw) / 2
	dy := (h - dh) / 2

	tuiDrawPanel(dx, dy, dw, dh, "Confirm", true)
	fmt.Print(tuiMoveTo(dx+2, dy+2) + tuiFgWhite + tuiPadR(msg, dw-4))
	fmt.Print(tuiMoveTo(dx+2, dy+4) + tuiFgBrightGreen + "[Y]" + tuiFgWhite + " Yes    " + tuiFgBrightRed + "[N]" + tuiFgWhite + " No")

	fmt.Print(tuiShowCursor)
	defer fmt.Print(tuiHideCursor)
	buf := make([]byte, 1)
	for {
		os.Stdin.Read(buf) //nolint:errcheck
		switch buf[0] {
		case 'y', 'Y':
			return true
		case 'n', 'N', 27:
			return false // ESC = no
		}
	}
}

// ── Menu dialog ───────────────────────────────────────────────────────────────

func tuiShowMenu(win *TUIWindow, title string, items []interface{}) string {
	w, h := tuiGetSize()

	maxLen := utf8.RuneCountInString(title)
	for _, item := range items {
		if l := utf8.RuneCountInString(toStr(item)); l > maxLen {
			maxLen = l
		}
	}
	dw := maxLen + 8
	dh := len(items) + 4
	dx := (w - dw) / 2
	dy := (h - dh) / 2

	selected := 0
	buf := make([]byte, 3)

	for {
		tuiDrawPanel(dx, dy, dw, dh, title, true)
		for i, item := range items {
			text := tuiPadR("  "+toStr(item), dw-2)
			if i == selected {
				fmt.Print(tuiMoveTo(dx+1, dy+2+i) + tuiBgBlue + tuiFgBrightWhite + tuiBold + text + tuiReset)
			} else {
				fmt.Print(tuiMoveTo(dx+1, dy+2+i) + tuiFgWhite + text + tuiReset)
			}
		}
		hint := tuiCenter("↑↓ Navigate  Enter=Select  Q=Cancel", dw-2)
		fmt.Print(tuiMoveTo(dx+1, dy+dh-2) + tuiDim + tuiFgCyan + hint + tuiReset)

		n, _ := os.Stdin.Read(buf)
		if n == 1 {
			switch buf[0] {
			case 13, 10: // Enter
				return toStr(items[selected])
			case 'q', 'Q', 27: // ESC
				return ""
			case 'k': // vim up
				if selected > 0 {
					selected--
				}
			case 'j': // vim down
				if selected < len(items)-1 {
					selected++
				}
			}
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
			switch buf[2] {
			case 65:
				if selected > 0 {
					selected--
				} // Up arrow
			case 66:
				if selected < len(items)-1 {
					selected++
				} // Down arrow
			}
		}
	}
}

// ── Alert dialog ──────────────────────────────────────────────────────────────

func tuiShowAlert(win *TUIWindow, msg string, colorName string) {
	w, h := tuiGetSize()
	lines := strings.Split(msg, "\n")
	maxLen := 0
	for _, l := range lines {
		if utf8.RuneCountInString(l) > maxLen {
			maxLen = utf8.RuneCountInString(l)
		}
	}
	dw := maxLen + 6
	if dw < 30 {
		dw = 30
	}
	dh := len(lines) + 5
	dx := (w - dw) / 2
	dy := (h - dh) / 2

	clr := tuiColor(colorName)
	tuiDrawPanel(dx, dy, dw, dh, " Alert ", true)
	for i, line := range lines {
		fmt.Print(tuiMoveTo(dx+3, dy+2+i) + clr + tuiBold + line + tuiReset)
	}
	hint := tuiCenter("Press any key to continue", dw-2)
	fmt.Print(tuiMoveTo(dx+1, dy+dh-2) + tuiDim + hint + tuiReset)

	buf := make([]byte, 1)
	os.Stdin.Read(buf) //nolint:errcheck
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func tuiGetWin(id string) *TUIWindow {
	if win, ok := tuiWindows[id]; ok {
		return win
	}
	return nil
}
