package main

// ── Spectator Missions ────────────────────────────────────────────────────────
//
// The biggest pain in hacking: running 10 tools, copy-pasting output between
// them, manually correlating findings, writing a report by hand.
//
// Missions solve this. A Mission is a structured attack pipeline built into
// the Spectator runtime. Every stage auto-feeds its results to the next stage,
// findings are tracked in a central store, and a full report is generated
// automatically at the end.
//
// New builtins added:
//
//   -- Mission lifecycle --
//   missionStart(name, target)          → mission_id
//   missionStage(id, name)              → prints stage header, tracks timing
//   missionFind(id, severity, title, detail)  → record a finding
//   missionNote(id, text)               → add a note to the mission log
//   missionData(id, key, value)         → store arbitrary data in mission context
//   missionGet(id, key)                 → retrieve stored mission data
//   missionEnd(id)                      → finalize, print summary
//   missionReport(id, filepath)         → generate full HTML report to file
//   missionFindings(id)                 → return list of all findings
//   missionSummary(id)                  → return summary map
//
//   -- Finding severity constants --
//   CRITICAL, HIGH, MEDIUM, LOW, INFO   → string constants for severity
//
//   -- Pipeline helpers --
//   pipe(list, func)                    → apply func to each item, collect results
//   pipeFilter(list, func)              → keep items where func returns true
//   pipeMap(list, func)                 → transform each item
//   gather(list)                        → flatten list of lists into one list
//   unique(list)                        → already exists, deduplicate
//   sortList(list)                      → sort list of strings alphabetically
//   tally(list)                         → count occurrences → map{item: count}
//   diff(list1, list2)                  → items in list1 not in list2
//   intersect(list1, list2)             → items in both lists
//   progress(current, total, label)     → print progress bar to stdout
//   table(headers, rows)               → print formatted ASCII table
//   colorize(text, color)              → wrap text in ANSI color
//   banner(text)                        → print big section banner
//   pad(s, width)                       → pad string to width
//   truncate(s, max)                    → truncate string with ...

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Mission data structures ───────────────────────────────────────────────────

type Finding struct {
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	Stage     string    `json:"stage"`
	Timestamp time.Time `json:"timestamp"`
}

type MissionStage struct {
	Name      string
	StartedAt time.Time
	EndedAt   time.Time
}

type Mission struct {
	ID        string
	Name      string
	Target    string
	StartedAt time.Time
	EndedAt   time.Time

	CurrentStage string
	Stages       []MissionStage
	Findings     []Finding
	Notes        []string
	Data         map[string]interface{}
	Log          []string

	mu sync.RWMutex
}

func (m *Mission) duration() string {
	end := m.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	d := end.Sub(m.StartedAt)
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return fmt.Sprintf("%.0fm %.0fs", d.Minutes(), d.Seconds()-60*float64(int(d.Minutes())))
}

func (m *Mission) countBySeverity(sev string) int {
	n := 0
	for _, f := range m.Findings {
		if strings.EqualFold(f.Severity, sev) {
			n++
		}
	}
	return n
}

// ── Mission store ─────────────────────────────────────────────────────────────

var (
	missionStore   = map[string]*Mission{}
	missionStoreMu sync.Mutex
	missionCounter int
)

func newMissionID() string {
	missionCounter++
	return fmt.Sprintf("mission_%d", missionCounter)
}

func getMission(id string) (*Mission, bool) {
	missionStoreMu.Lock()
	defer missionStoreMu.Unlock()
	m, ok := missionStore[id]
	return m, ok
}

// ── Severity constants ────────────────────────────────────────────────────────

const (
	SEV_CRITICAL = "CRITICAL"
	SEV_HIGH     = "HIGH"
	SEV_MEDIUM   = "MEDIUM"
	SEV_LOW      = "LOW"
	SEV_INFO     = "INFO"
)

// ── Mission builtin dispatcher ────────────────────────────────────────────────

func (interp *Interpreter) missionBuiltin(name string, args []interface{}) (interface{}, error) {
	switch name {

	// ── missionStart(name, target) → id ────────────────────────────────────
	case "missionStart":
		mName := "Unnamed Mission"
		target := ""
		if len(args) >= 1 {
			mName = toStr(args[0])
		}
		if len(args) >= 2 {
			target = toStr(args[1])
		}

		id := newMissionID()
		m := &Mission{
			ID:        id,
			Name:      mName,
			Target:    target,
			StartedAt: time.Now(),
			Data:      make(map[string]interface{}),
		}
		missionStoreMu.Lock()
		missionStore[id] = m
		missionStoreMu.Unlock()

		// Print mission header
		fmt.Println()
		fmt.Println(colorBold("  ╔══════════════════════════════════════════════════════╗"))
		fmt.Println(colorBold("  ║  MISSION: " + padRight(mName, 43) + "║"))
		if target != "" {
			fmt.Println(colorBold("  ║  TARGET : " + padRight(target, 43) + "║"))
		}
		fmt.Println(colorBold("  ║  STARTED: " + padRight(m.StartedAt.Format("2006-01-02 15:04:05"), 43) + "║"))
		fmt.Println(colorBold("  ╚══════════════════════════════════════════════════════╝"))
		fmt.Println()
		return id, nil

	// ── missionStage(id, name) ─────────────────────────────────────────────
	case "missionStage":
		if len(args) < 2 {
			return nil, fmt.Errorf("missionStage() requires id, name")
		}
		id := toStr(args[0])
		stage := toStr(args[1])
		m, ok := getMission(id)
		if !ok {
			return nil, fmt.Errorf("missionStage: unknown mission %q", id)
		}

		m.mu.Lock()
		// Close previous stage timing
		if len(m.Stages) > 0 {
			m.Stages[len(m.Stages)-1].EndedAt = time.Now()
		}
		m.Stages = append(m.Stages, MissionStage{Name: stage, StartedAt: time.Now()})
		m.CurrentStage = stage
		m.mu.Unlock()

		fmt.Println()
		fmt.Println(colorCyan("  ┌─────────────────────────────────────────────────────"))
		fmt.Println(colorCyan("  │ ") + colorBold("STAGE: "+stage))
		fmt.Println(colorCyan("  │ ") + colorDim(time.Now().Format("15:04:05")))
		fmt.Println(colorCyan("  └─────────────────────────────────────────────────────"))
		return nil, nil

	// ── missionFind(id, severity, title, detail) ───────────────────────────
	case "missionFind":
		if len(args) < 3 {
			return nil, fmt.Errorf("missionFind() requires id, severity, title")
		}
		id := toStr(args[0])
		severity := strings.ToUpper(toStr(args[1]))
		title := toStr(args[2])
		detail := ""
		if len(args) >= 4 {
			detail = toStr(args[3])
		}

		m, ok := getMission(id)
		if !ok {
			return nil, fmt.Errorf("missionFind: unknown mission %q", id)
		}

		f := Finding{
			Severity:  severity,
			Title:     title,
			Detail:    detail,
			Stage:     m.CurrentStage,
			Timestamp: time.Now(),
		}
		m.mu.Lock()
		m.Findings = append(m.Findings, f)
		m.mu.Unlock()

		// Color by severity
		sevColor := map[string]func(string) string{
			"CRITICAL": colorRed,
			"HIGH":     colorRed,
			"MEDIUM":   colorYellow,
			"LOW":      colorCyan,
			"INFO":     colorGreen,
		}
		colorFn, ok2 := sevColor[severity]
		if !ok2 {
			colorFn = colorGreen
		}

		fmt.Println(colorFn("  [FINDING] [" + severity + "] " + title))
		if detail != "" {
			for _, line := range strings.Split(detail, "\n") {
				fmt.Println(colorDim("    " + line))
			}
		}
		return nil, nil

	// ── missionNote(id, text) ─────────────────────────────────────────────
	case "missionNote":
		if len(args) < 2 {
			return nil, nil
		}
		id := toStr(args[0])
		note := toStr(args[1])
		m, ok := getMission(id)
		if !ok {
			return nil, nil
		}
		m.mu.Lock()
		m.Notes = append(m.Notes, note)
		m.mu.Unlock()
		fmt.Println(colorDim("  [NOTE] " + note))
		return nil, nil

	// ── missionData(id, key, value) ────────────────────────────────────────
	case "missionData":
		if len(args) < 3 {
			return nil, fmt.Errorf("missionData() requires id, key, value")
		}
		id := toStr(args[0])
		key := toStr(args[1])
		val := args[2]
		m, ok := getMission(id)
		if !ok {
			return nil, fmt.Errorf("missionData: unknown mission %q", id)
		}
		m.mu.Lock()
		m.Data[key] = val
		m.mu.Unlock()
		return nil, nil

	// ── missionGet(id, key) ────────────────────────────────────────────────
	case "missionGet":
		if len(args) < 2 {
			return nil, nil
		}
		id := toStr(args[0])
		key := toStr(args[1])
		m, ok := getMission(id)
		if !ok {
			return nil, nil
		}
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.Data[key], nil

	// ── missionEnd(id) ────────────────────────────────────────────────────
	case "missionEnd":
		if len(args) < 1 {
			return nil, nil
		}
		id := toStr(args[0])
		m, ok := getMission(id)
		if !ok {
			return nil, nil
		}
		m.mu.Lock()
		m.EndedAt = time.Now()
		if len(m.Stages) > 0 {
			m.Stages[len(m.Stages)-1].EndedAt = m.EndedAt
		}
		m.mu.Unlock()

		crit := m.countBySeverity("CRITICAL")
		high := m.countBySeverity("HIGH")
		med := m.countBySeverity("MEDIUM")
		low := m.countBySeverity("LOW")
		info := m.countBySeverity("INFO")

		fmt.Println()
		fmt.Println(colorBold("  ╔══════════════════════════════════════════════════════╗"))
		fmt.Println(colorBold("  ║  MISSION COMPLETE: " + padRight(m.Name, 34) + "║"))
		fmt.Println(colorBold("  ╠══════════════════════════════════════════════════════╣"))
		fmt.Println(colorBold("  ║  Duration : " + padRight(m.duration(), 41) + "║"))
		fmt.Println(colorBold("  ║  Stages   : " + padRight(fmt.Sprintf("%d completed", len(m.Stages)), 41) + "║"))
		fmt.Println(colorBold("  ║  Findings : " + padRight(fmt.Sprintf("%d total", len(m.Findings)), 41) + "║"))
		fmt.Println(colorBold("  ╠══════════════════════════════════════════════════════╣"))
		if crit > 0 {
			fmt.Println(colorRed("  ║  CRITICAL : " + padRight(fmt.Sprintf("%d", crit), 41) + "║"))
		}
		if high > 0 {
			fmt.Println(colorRed("  ║  HIGH     : " + padRight(fmt.Sprintf("%d", high), 41) + "║"))
		}
		if med > 0 {
			fmt.Println(colorYellow("  ║  MEDIUM   : " + padRight(fmt.Sprintf("%d", med), 41) + "║"))
		}
		if low > 0 {
			fmt.Println(colorCyan("  ║  LOW      : " + padRight(fmt.Sprintf("%d", low), 41) + "║"))
		}
		if info > 0 {
			fmt.Println(colorGreen("  ║  INFO     : " + padRight(fmt.Sprintf("%d", info), 41) + "║"))
		}
		fmt.Println(colorBold("  ╚══════════════════════════════════════════════════════╝"))
		fmt.Println()
		return nil, nil

	// ── missionReport(id, filepath) → generates HTML report ───────────────
	case "missionReport":
		if len(args) < 2 {
			return nil, fmt.Errorf("missionReport() requires id, filepath")
		}
		id := toStr(args[0])
		filePath := toStr(args[1])
		m, ok := getMission(id)
		if !ok {
			return nil, fmt.Errorf("missionReport: unknown mission %q", id)
		}

		htmlContent := buildHTMLReport(m)
		if err := os.WriteFile(filePath, []byte(htmlContent), 0644); err != nil {
			return nil, fmt.Errorf("missionReport: write failed: %v", err)
		}
		fmt.Println(colorGreen("  [✓] Report saved: " + filePath))
		fmt.Println(colorDim("      Open in any browser to view."))
		return filePath, nil

	// ── missionFindings(id) → list of finding maps ─────────────────────────
	case "missionFindings":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		id := toStr(args[0])
		m, ok := getMission(id)
		if !ok {
			return []interface{}{}, nil
		}
		m.mu.RLock()
		defer m.mu.RUnlock()
		out := make([]interface{}, len(m.Findings))
		for i, f := range m.Findings {
			out[i] = map[string]interface{}{
				"severity": f.Severity,
				"title":    f.Title,
				"detail":   f.Detail,
				"stage":    f.Stage,
			}
		}
		return out, nil

	// ── missionSummary(id) → summary map ──────────────────────────────────
	case "missionSummary":
		if len(args) < 1 {
			return nil, nil
		}
		id := toStr(args[0])
		m, ok := getMission(id)
		if !ok {
			return nil, nil
		}
		return map[string]interface{}{
			"name":     m.Name,
			"target":   m.Target,
			"duration": m.duration(),
			"findings": float64(len(m.Findings)),
			"stages":   float64(len(m.Stages)),
			"critical": float64(m.countBySeverity("CRITICAL")),
			"high":     float64(m.countBySeverity("HIGH")),
			"medium":   float64(m.countBySeverity("MEDIUM")),
			"low":      float64(m.countBySeverity("LOW")),
			"info":     float64(m.countBySeverity("INFO")),
		}, nil
	}
	return nil, fmt.Errorf("unknown mission builtin: %q", name)
}

// ── Pipeline & utility builtins ────────────────────────────────────────────────

func (interp *Interpreter) pipelineBuiltin(name string, args []interface{}, argExprs []Expr, env *Env) (interface{}, error) {
	switch name {

	// pipe(list, func_name) → apply func to each item, collect non-nil results
	case "pipe":
		if len(args) < 2 {
			return nil, fmt.Errorf("pipe() requires list, func")
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return nil, fmt.Errorf("pipe: first arg must be a list")
		}
		fnName, ok2 := args[1].(string)
		if !ok2 {
			// Try as UserFunc
			fn, ok3 := args[1].(*UserFunc)
			if !ok3 {
				return nil, fmt.Errorf("pipe: second arg must be a function name or func")
			}
			var out []interface{}
			for _, item := range list {
				child := NewEnv(fn.Env)
				if len(fn.Params) > 0 {
					child.Set(fn.Params[0], item)
				}
				var result interface{}
				err := interp.execBlock(fn.Body, child)
				if err != nil {
					if ret, ok := err.(ReturnSignal); ok {
						result = ret.Value
					} else {
						return nil, err
					}
				}
				if result != nil {
					out = append(out, result)
				}
			}
			return out, nil
		}
		var out []interface{}
		for _, item := range list {
			callExpr := &CallExpr{Callee: fnName, Args: []Expr{&StringLit{Value: toStr(item)}}}
			result, err := interp.callFunc(callExpr, env)
			if err != nil {
				continue
			}
			if result != nil {
				out = append(out, result)
			}
		}
		return out, nil

	// progress(current, total, label) — prints a live progress bar
	case "progress":
		if len(args) < 2 {
			return nil, nil
		}
		cur := int(toFloat(args[0]))
		total := int(toFloat(args[1]))
		label := ""
		if len(args) >= 3 {
			label = toStr(args[2])
		}
		if total == 0 {
			total = 1
		}
		pct := float64(cur) / float64(total)
		filled := int(pct * 30)
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 30-filled)
		pctStr := fmt.Sprintf("%3.0f%%", pct*100)
		line := fmt.Sprintf("\r  [%s] %s  %d/%d  %s", bar, pctStr, cur, total, label)
		fmt.Print(colorCyan(line))
		if cur >= total {
			fmt.Println()
		}
		return nil, nil

	// table(headers_list, rows_list_of_lists) — print formatted ASCII table
	case "table":
		if len(args) < 2 {
			return nil, nil
		}
		headers, ok1 := args[0].([]interface{})
		rows, ok2 := args[1].([]interface{})
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("table() requires list of headers and list of rows")
		}

		// Calculate column widths
		widths := make([]int, len(headers))
		for i, h := range headers {
			if l := len(toStr(h)); l > widths[i] {
				widths[i] = l
			}
		}
		for _, row := range rows {
			if rowList, ok := row.([]interface{}); ok {
				for i, cell := range rowList {
					if i < len(widths) {
						if l := len(toStr(cell)); l > widths[i] {
							widths[i] = l
						}
					}
				}
			}
		}

		// Build separator
		sep := "  +"
		for _, w := range widths {
			sep += strings.Repeat("-", w+2) + "+"
		}

		// Print header
		fmt.Println(colorCyan(sep))
		hrow := "  |"
		for i, h := range headers {
			hrow += " " + padRight(toStr(h), widths[i]) + " |"
		}
		fmt.Println(colorBold(hrow))
		fmt.Println(colorCyan(sep))

		// Print rows
		for _, row := range rows {
			rrow := "  |"
			if rowList, ok := row.([]interface{}); ok {
				for i := 0; i < len(widths); i++ {
					cell := ""
					if i < len(rowList) {
						cell = toStr(rowList[i])
					}
					rrow += " " + padRight(cell, widths[i]) + " |"
				}
			}
			fmt.Println(rrow)
		}
		fmt.Println(colorCyan(sep))
		return nil, nil

	// tally(list) → map of {item: count}
	case "tally":
		if len(args) < 1 {
			return map[string]interface{}{}, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return map[string]interface{}{}, nil
		}
		counts := map[string]interface{}{}
		for _, item := range list {
			k := toStr(item)
			if v, ok := counts[k]; ok {
				counts[k] = v.(float64) + 1
			} else {
				counts[k] = float64(1)
			}
		}
		return counts, nil

	// sortList(list) → alphabetically sorted list
	case "sortList":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		list, ok := args[0].([]interface{})
		if !ok {
			return args[0], nil
		}
		cp := make([]interface{}, len(list))
		copy(cp, list)
		sort.Slice(cp, func(i, j int) bool { return toStr(cp[i]) < toStr(cp[j]) })
		return cp, nil

	// diff(list1, list2) → items in list1 not in list2
	case "diff":
		if len(args) < 2 {
			return []interface{}{}, nil
		}
		l1, ok1 := args[0].([]interface{})
		l2, ok2 := args[1].([]interface{})
		if !ok1 || !ok2 {
			return []interface{}{}, nil
		}
		set2 := map[string]bool{}
		for _, v := range l2 {
			set2[toStr(v)] = true
		}
		var out []interface{}
		for _, v := range l1 {
			if !set2[toStr(v)] {
				out = append(out, v)
			}
		}
		return out, nil

	// intersect(list1, list2) → items in both lists
	case "intersect":
		if len(args) < 2 {
			return []interface{}{}, nil
		}
		l1, ok1 := args[0].([]interface{})
		l2, ok2 := args[1].([]interface{})
		if !ok1 || !ok2 {
			return []interface{}{}, nil
		}
		set2 := map[string]bool{}
		for _, v := range l2 {
			set2[toStr(v)] = true
		}
		var out []interface{}
		for _, v := range l1 {
			if set2[toStr(v)] {
				out = append(out, v)
			}
		}
		return out, nil

	// gather(list_of_lists) → flat list
	case "gather":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		outer, ok := args[0].([]interface{})
		if !ok {
			return args[0], nil
		}
		var out []interface{}
		for _, item := range outer {
			if sub, ok := item.([]interface{}); ok {
				out = append(out, sub...)
			} else if item != nil {
				out = append(out, item)
			}
		}
		return out, nil

	// banner(text) → print big section banner
	case "banner":
		if len(args) < 1 {
			return nil, nil
		}
		text := toStr(args[0])
		line := strings.Repeat("═", len(text)+6)
		fmt.Println()
		fmt.Println(colorBold("  ╔" + line + "╗"))
		fmt.Println(colorBold("  ║   " + text + "   ║"))
		fmt.Println(colorBold("  ╚" + line + "╝"))
		fmt.Println()
		return nil, nil

	// pad(s, width) → right-pad string to width
	case "pad":
		if len(args) < 2 {
			return toStr(args[0]), nil
		}
		return padRight(toStr(args[0]), int(toFloat(args[1]))), nil

	// truncate(s, max) → shorten with ...
	case "truncate":
		if len(args) < 2 {
			return toStr(args[0]), nil
		}
		s := toStr(args[0])
		max := int(toFloat(args[1]))
		if len(s) <= max {
			return s, nil
		}
		if max <= 3 {
			return s[:max], nil
		}
		return s[:max-3] + "...", nil

	// colorize(text, color) → ANSI colored string
	case "colorize":
		if len(args) < 2 {
			return toStr(args[0]), nil
		}
		text := toStr(args[0])
		color := strings.ToLower(toStr(args[1]))
		switch color {
		case "red":
			return colorRed(text), nil
		case "green":
			return colorGreen(text), nil
		case "cyan":
			return colorCyan(text), nil
		case "yellow":
			return colorYellow(text), nil
		case "magenta":
			return colorMagenta(text), nil
		case "bold":
			return colorBold(text), nil
		case "dim":
			return colorDim(text), nil
		}
		return text, nil

	// severity constants
	case "CRITICAL":
		return SEV_CRITICAL, nil
	case "HIGH":
		return SEV_HIGH, nil
	case "MEDIUM":
		return SEV_MEDIUM, nil
	case "LOW":
		return SEV_LOW, nil
	case "INFO":
		return SEV_INFO, nil
	}

	return nil, fmt.Errorf("unknown pipeline builtin: %q", name)
}

// ── HTML Report Generator ─────────────────────────────────────────────────────

func buildHTMLReport(m *Mission) string {
	crit := m.countBySeverity("CRITICAL")
	high := m.countBySeverity("HIGH")
	med := m.countBySeverity("MEDIUM")
	low := m.countBySeverity("LOW")
	info := m.countBySeverity("INFO")
	total := len(m.Findings)

	riskColor := "#22c55e"
	riskLabel := "LOW RISK"
	riskBg := "#052e16"
	if med > 0 {
		riskColor = "#eab308"
		riskLabel = "MEDIUM RISK"
		riskBg = "#1c1a05"
	}
	if high > 0 {
		riskColor = "#f97316"
		riskLabel = "HIGH RISK"
		riskBg = "#1c0d02"
	}
	if crit > 0 {
		riskColor = "#ef4444"
		riskLabel = "CRITICAL RISK"
		riskBg = "#1c0202"
	}

	// Sort findings: CRITICAL→HIGH→MEDIUM→LOW→INFO
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sorted := make([]Finding, len(m.Findings))
	copy(sorted, m.Findings)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sevOrder[sorted[j].Severity] < sevOrder[sorted[i].Severity] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	sevColor := map[string]string{"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#22c55e"}
	sevBg := map[string]string{"CRITICAL": "#2d0a0a", "HIGH": "#2d1500", "MEDIUM": "#252000", "LOW": "#0a1520", "INFO": "#051a0f"}

	endedStr := "In progress"
	if !m.EndedAt.IsZero() {
		endedStr = m.EndedAt.Format("2006-01-02 15:04:05")
	}

	pct := func(n int) int {
		if total == 0 {
			return 0
		}
		p := n * 100 / total
		if p == 0 && n > 0 {
			return 1
		}
		return p
	}

	var w strings.Builder

	w.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	w.WriteString("<meta charset=\"UTF-8\">\n")
	w.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	w.WriteString("<title>" + html.EscapeString(m.Name) + " — Spectator Report</title>\n")
	w.WriteString(`<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080d17;color:#cbd5e1;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
.page{max-width:960px;margin:0 auto;padding:2rem 1.5rem}
.sec{margin-bottom:2rem}
.sec-title{font-size:11px;font-weight:700;letter-spacing:.12em;color:#475569;text-transform:uppercase;margin-bottom:1rem;padding-bottom:8px;border-bottom:1px solid #1e293b}
pre{margin:0}
</style>
</head>
<body><div class="page">
`)

	// ── HEADER ──
	w.WriteString(`<div style="background:` + riskBg + `;border:1px solid ` + riskColor + `;border-radius:12px;padding:2rem;margin-bottom:2rem;">`)
	w.WriteString(`<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">`)
	w.WriteString(`<div>`)
	w.WriteString(`<div style="font-size:11px;font-weight:700;letter-spacing:.15em;color:` + riskColor + `;text-transform:uppercase;margin-bottom:6px;">SPECTATOR MISSION REPORT</div>`)
	w.WriteString(`<h1 style="font-size:1.75rem;color:#f0f6ff;font-weight:700;margin-bottom:4px;">` + html.EscapeString(m.Name) + `</h1>`)
	w.WriteString(`<div style="color:#64748b;font-size:13px;">Target: <strong style="color:#38bdf8;font-family:monospace;">` + html.EscapeString(m.Target) + `</strong></div>`)
	w.WriteString(`</div>`)
	w.WriteString(`<div style="background:` + riskBg + `;border:1px solid ` + riskColor + `;border-radius:8px;padding:.75rem 1.25rem;text-align:center;">`)
	w.WriteString(`<div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:` + riskColor + `;text-transform:uppercase;margin-bottom:4px;">Risk Level</div>`)
	w.WriteString(`<div style="font-size:1.5rem;font-weight:800;color:` + riskColor + `;">` + riskLabel + `</div>`)
	w.WriteString(`</div></div>`)
	w.WriteString(`<div style="display:flex;flex-wrap:wrap;gap:2rem;margin-top:1.25rem;padding-top:1.25rem;border-top:1px solid #1e293b;font-size:12px;color:#475569;font-family:monospace;">`)
	w.WriteString(`<span>Started: <strong style="color:#94a3b8;">` + m.StartedAt.Format("2006-01-02 15:04:05") + `</strong></span>`)
	w.WriteString(`<span>Ended: <strong style="color:#94a3b8;">` + endedStr + `</strong></span>`)
	w.WriteString(`<span>Duration: <strong style="color:#94a3b8;">` + m.duration() + `</strong></span>`)
	w.WriteString(fmt.Sprintf(`<span>Stages: <strong style="color:#94a3b8;">%d</strong></span>`, len(m.Stages)))
	w.WriteString(`</div></div>`)

	// ── STAT CARDS ──
	type card struct {
		bg, border, textColor, label string
		n                            int
	}
	cards := []card{
		{"#0f172a", "#1e293b", "#e2e8f0", "Total", total},
		{"#2d0a0a", "#7f1d1d", "#ef4444", "Critical", crit},
		{"#2d1500", "#7c2d12", "#f97316", "High", high},
		{"#252000", "#713f12", "#eab308", "Medium", med},
		{"#0a1520", "#1e3a5f", "#3b82f6", "Low", low},
		{"#051a0f", "#14532d", "#22c55e", "Info", info},
	}
	w.WriteString(`<div style="display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:2rem;">`)
	for _, c := range cards {
		w.WriteString(fmt.Sprintf(
			`<div style="background:%s;border:1px solid %s;border-radius:10px;padding:1rem;text-align:center;">`,
			c.bg, c.border))
		w.WriteString(fmt.Sprintf(`<div style="font-size:2rem;font-weight:800;color:%s;">%d</div>`, c.textColor, c.n))
		w.WriteString(fmt.Sprintf(`<div style="font-size:10px;color:%s;text-transform:uppercase;letter-spacing:.1em;margin-top:2px;">%s</div>`, c.border, c.label))
		w.WriteString(`</div>`)
	}
	w.WriteString(`</div>`)

	// ── SEVERITY BAR CHART ──
	w.WriteString(`<div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:1.25rem;margin-bottom:2rem;">`)
	w.WriteString(`<div class="sec-title">Severity Distribution</div>`)
	w.WriteString(`<div style="display:flex;flex-direction:column;gap:10px;">`)
	for _, sc := range []struct {
		sev string
		n   int
	}{
		{"CRITICAL", crit}, {"HIGH", high}, {"MEDIUM", med}, {"LOW", low}, {"INFO", info},
	} {
		clr := sevColor[sc.sev]
		p := pct(sc.n)
		minW := "0"
		if sc.n > 0 {
			minW = "4px"
		}
		w.WriteString(`<div style="display:flex;align-items:center;gap:12px;">`)
		w.WriteString(fmt.Sprintf(`<span style="width:65px;font-size:10px;font-weight:700;color:%s;text-transform:uppercase;letter-spacing:.08em;text-align:right;">%s</span>`, clr, sc.sev))
		w.WriteString(`<div style="flex:1;background:#0a0f1a;border-radius:4px;height:16px;overflow:hidden;">`)
		w.WriteString(fmt.Sprintf(`<div style="width:%d%%;background:%s;height:100%%;border-radius:4px;min-width:%s;"></div>`, p, clr, minW))
		w.WriteString(`</div>`)
		w.WriteString(fmt.Sprintf(`<span style="width:24px;font-size:11px;color:#475569;text-align:right;font-family:monospace;">%d</span>`, sc.n))
		w.WriteString(`</div>`)
	}
	w.WriteString(`</div></div>`)

	// ── FINDINGS ──
	w.WriteString(`<div class="sec">`)
	w.WriteString(fmt.Sprintf(`<div class="sec-title">Findings (%d)</div>`, total))
	if total == 0 {
		w.WriteString(`<div style="color:#374151;font-style:italic;padding:2rem;text-align:center;background:#0f172a;border-radius:8px;">No findings recorded.</div>`)
	}
	for _, f := range sorted {
		c := sevColor[f.Severity]
		if c == "" {
			c = "#6b7280"
		}
		bg := sevBg[f.Severity]
		if bg == "" {
			bg = "#1e293b"
		}
		w.WriteString(fmt.Sprintf(`<div style="background:%s;border-radius:8px;padding:18px 20px;margin-bottom:10px;border:1px solid %s;border-left:4px solid %s;">`, bg, c, c))
		w.WriteString(`<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">`)
		w.WriteString(fmt.Sprintf(`<span style="background:%s;color:#fff;font-size:10px;font-weight:800;padding:3px 10px;border-radius:4px;letter-spacing:.1em;">%s</span>`, c, html.EscapeString(f.Severity)))
		w.WriteString(fmt.Sprintf(`<span style="color:#f0f6ff;font-weight:600;font-size:14px;">%s</span>`, html.EscapeString(f.Title)))
		w.WriteString(`</div>`)
		w.WriteString(fmt.Sprintf(`<div style="color:#4a5568;font-size:11px;font-family:monospace;">Stage: %s &nbsp;·&nbsp; %s</div>`, html.EscapeString(f.Stage), f.Timestamp.Format("15:04:05")))
		if f.Detail != "" {
			w.WriteString(`<pre style="margin-top:10px;padding:12px;background:#0d1117;border-radius:6px;font-size:12px;color:#8b949e;white-space:pre-wrap;overflow-x:auto;border:1px solid #21262d;">`)
			w.WriteString(html.EscapeString(f.Detail))
			w.WriteString(`</pre>`)
		}
		w.WriteString(`</div>`)
	}
	w.WriteString(`</div>`)

	// ── STAGES ──
	w.WriteString(`<div class="sec">`)
	w.WriteString(fmt.Sprintf(`<div class="sec-title">Stages (%d)</div>`, len(m.Stages)))
	w.WriteString(`<div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:0 1.25rem;">`)
	for i, s := range m.Stages {
		dur := ""
		if !s.EndedAt.IsZero() {
			d := s.EndedAt.Sub(s.StartedAt)
			if d.Seconds() < 60 {
				dur = fmt.Sprintf("%.1fs", d.Seconds())
			} else {
				dur = fmt.Sprintf("%.0fm%.0fs", d.Minutes(), d.Seconds()-60*float64(int(d.Minutes())))
			}
		}
		w.WriteString(`<div style="display:flex;align-items:center;gap:14px;padding:12px 0;border-bottom:1px solid #161d2d;">`)
		w.WriteString(fmt.Sprintf(`<div style="width:32px;height:32px;border-radius:50%%;background:#0f172a;border:2px solid #1e3a5f;color:#38bdf8;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;">%d</div>`, i+1))
		w.WriteString(fmt.Sprintf(`<div style="flex:1;color:#cbd5e1;font-size:13px;font-weight:500;">%s</div>`, html.EscapeString(s.Name)))
		w.WriteString(fmt.Sprintf(`<div style="color:#334155;font-size:11px;font-family:monospace;background:#0a0f1a;padding:3px 8px;border-radius:4px;">%s</div>`, dur))
		w.WriteString(`</div>`)
	}
	w.WriteString(`</div></div>`)

	// ── NOTES ──
	if len(m.Notes) > 0 {
		w.WriteString(`<div class="sec">`)
		w.WriteString(`<div class="sec-title">Notes</div>`)
		w.WriteString(`<ul style="padding-left:0;list-style:none;">`)
		for _, note := range m.Notes {
			w.WriteString(`<li style="color:#64748b;font-size:13px;padding:6px 0 6px 16px;border-left:2px solid #1e3a5f;margin-bottom:6px;font-family:monospace;">`)
			w.WriteString(html.EscapeString(note))
			w.WriteString(`</li>`)
		}
		w.WriteString(`</ul></div>`)
	}

	// ── FOOTER ──
	w.WriteString(`<div style="text-align:center;color:#1e293b;font-size:11px;margin-top:3rem;padding-top:1rem;border-top:1px solid #0f172a;font-family:monospace;">`)
	w.WriteString(`Generated by Spectator v2.0 &nbsp;·&nbsp; ` + time.Now().Format("2006-01-02 15:04:05") + ` &nbsp;·&nbsp; spectator-lang.dev`)
	w.WriteString(`</div>`)

	w.WriteString(`</div></body></html>`)
	return w.String()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
