package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
//
//	Spectator — Cybersecurity Scripting Language  v2.0.0
//	"See Everything. Miss Nothing."
//
//	Usage:
//	  spectator run <file.str>           Run a Spectator script
//	  spectator repl                     Interactive REPL
//	  spectator build <f.str> to <out> for <platform>  Compile to standalone exe
//	  spectator space <command>          Package manager (Space)
//	  spectator version                  Show version
//	  spectator help                     Show this help
//
// ─────────────────────────────────────────────────────────────────────────────

const (
	spectatorVersion = "2.0.0"
	spectatorTagline = "See Everything. Miss Nothing."
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "run":
		if len(os.Args) < 3 {
			printError("Usage: spectator run <file.str>")
			os.Exit(1)
		}
		runFile(os.Args[2])

	case "repl":
		runREPL()

	case "build":
		// spectator build <file.str> to <output> for <platform>
		if len(os.Args) < 6 || os.Args[3] != "to" || os.Args[5] != "for" {
			printError("Usage: spectator build <file.str> to <output> for <platform>")
			fmt.Println()
			fmt.Println("  Platforms: windows  linux  mac  linuxarm  win32  freebsd  macarm")
			os.Exit(1)
		}
		buildScript(os.Args[2], os.Args[4], os.Args[6])

	case "space", "Space":
		RunSpace(os.Args[2:])

	case "version", "--version", "-v":
		printVersion()

	case "help", "--help", "-h":
		printHelp()

	default:
		printError("Unknown command: " + os.Args[1])
		fmt.Println()
		printHelp()
		os.Exit(1)
	}
}

// ── Run a .str script ─────────────────────────────────────────────────────────

func runFile(path string) {
	src, err := os.ReadFile(path)
	if err != nil {
		printError("Cannot read file: " + err.Error())
		os.Exit(1)
	}

	lx := NewLexer(string(src))
	tokens, err := lx.Tokenize()
	if err != nil {
		printError("Lex error in " + path + ": " + err.Error())
		os.Exit(1)
	}

	pr := NewParser(tokens)
	prog, err := pr.Parse()
	if err != nil {
		printError("Parse error in " + path + ": " + err.Error())
		os.Exit(1)
	}

	interp := NewInterpreter()
	if err := interp.Run(prog); err != nil {
		printError("Runtime error: " + err.Error())
		os.Exit(1)
	}
}

// ── REPL ──────────────────────────────────────────────────────────────────────

func runREPL() {
	printBanner()
	fmt.Println(colorDim("  Interactive REPL — type Spectator code, press Enter to run."))
	fmt.Println(colorDim("  Type 'exit' or 'quit' to leave.  Type 'help' for commands."))
	fmt.Println()

	interp := NewInterpreter()
	buf := ""
	reader := bufio.NewReader(os.Stdin)

	for {
		prompt := colorCyan("  ◈ ")
		if buf != "" {
			prompt = colorDim("  · ")
		}
		fmt.Print(prompt)

		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			break
		}
		line = strings.TrimRight(line, "\r\n")

		switch strings.TrimSpace(line) {
		case "exit", "quit":
			fmt.Println(colorDim("\n  Goodbye.\n"))
			return
		case "help":
			printReplHelp()
			continue
		case "clear":
			fmt.Print("\033[2J\033[H")
			continue
		case "":
			if buf == "" {
				continue
			}
		}

		buf += line + "\n"

		// Try to parse and run
		lx := NewLexer(buf)
		tokens, lexErr := lx.Tokenize()
		if lexErr != nil {
			// Might be incomplete — wait for more input
			if strings.Contains(lexErr.Error(), "unexpected EOF") ||
				strings.Contains(lexErr.Error(), "unterminated") {
				continue
			}
			fmt.Println(colorRed("  [!] " + lexErr.Error()))
			buf = ""
			continue
		}

		pr := NewParser(tokens)
		prog, parseErr := pr.Parse()
		if parseErr != nil {
			// Incomplete block — wait for more
			msg := parseErr.Error()
			if strings.Contains(msg, "expected }") ||
				strings.Contains(msg, "unexpected EOF") ||
				strings.Contains(msg, "unexpected token \"\"") {
				continue
			}
			fmt.Println(colorRed("  [!] " + msg))
			buf = ""
			continue
		}

		buf = ""
		if err := interp.Run(prog); err != nil {
			fmt.Println(colorRed("  [!] " + err.Error()))
		}
	}
}

// ── Build ─────────────────────────────────────────────────────────────────────

func buildScript(src, out, platform string) {
	// Delegate to existing build engine in build.go
	// Format: build <src> to <out> for <platform>
	RunBuild([]string{src, "to", out, "for", platform})
}

// ── Print helpers ─────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Println()
	fmt.Println(colorCyan("  ╔══════════════════════════════════════════════════════════╗"))
	fmt.Println(colorCyan("  ║") + colorBold("                                                          ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██╗  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██║  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██║  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██║  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ") + colorCyan("║"))
	fmt.Println(colorCyan("  ║") + colorBold("                                                          ") + colorCyan("║"))
	fmt.Printf(colorCyan("  ║")+"   "+colorGreen("%-54s")+colorCyan("║\n"), spectatorTagline)
	fmt.Printf(colorCyan("  ║")+"   "+colorDim("%-54s")+colorCyan("║\n"), "v"+spectatorVersion+"  |  Cybersecurity Scripting Language")
	fmt.Println(colorCyan("  ╚══════════════════════════════════════════════════════════╝"))
	fmt.Println()
}

func printVersion() {
	fmt.Println()
	fmt.Println(colorBold("  Spectator v" + spectatorVersion))
	fmt.Println(colorDim("  " + spectatorTagline))
	fmt.Println(colorDim("  https://github.com/CzaxStudio/Spectator"))
	fmt.Println()
}

func printError(msg string) {
	fmt.Println(colorRed("  [!] " + msg))
}

func printHelp() {
	printBanner()

	fmt.Println(colorBold("  USAGE"))
	fmt.Println()
	printCmd("spectator run <file.str>", "Run a Spectator script")
	printCmd("spectator repl", "Interactive REPL")
	printCmd("spectator build <f.str> to <out> for <os>", "Compile to standalone binary")
	printCmd("spectator space <command>", "Package manager (Space)")
	printCmd("spectator version", "Show version")
	printCmd("spectator help", "Show this help")
	fmt.Println()

	fmt.Println(colorBold("  LANGUAGE FEATURES"))
	fmt.Println()
	printSection("Variables", "x = 42 | let y = \"hello\" | pi = 3.14")
	printSection("f-strings", "f\"Hello {name}, you are {age}\"")
	printSection("Concat", "\"Hello \" --> name --> \"!\"")
	printSection("Maps", `m = {"key": "val"} | m.key | m["key"]`)
	printSection("Lists", `tools = ["nmap","burp"] | tools[0]`)
	printSection("If", "if x > 10 { } elseif x == 5 { } else { }")
	printSection("Loop", "loop 10 { Trace(_i) } | loop { break }")
	printSection("Each", "each item, idx : list { } | each val, key : map { }")
	printSection("Match", "match x { \"a\" => { } _ => { } }")
	printSection("Functions", "func greet(name) { return \"Hi \" --> name }")
	printSection("Try/Catch", "try { risky() } catch e { Trace(e) }")
	printSection("Spawn", "spawn longTask(target)  -- goroutine")
	printSection("Import", "#Import coffee  |  #Import ghost")
	printSection("Runner", "out = # runner<?whoami>")
	fmt.Println()

	fmt.Println(colorBold("  BUILT-IN MODULES"))
	fmt.Println()
	printSection("Recon", "do --> Recon(host)  |  do --> PortScan(host, 1, 1024)")
	printSection("DNS", "resolve(d)  lookupMX(d)  lookupNS(d)  lookupTXT(d)")
	printSection("Web", "do --> HTTPProbe(url)  |  do --> HeaderAudit(url)")
	printSection("SSL", "do --> SSLInfo(host)")
	printSection("OSINT", "do --> WHOIs(d)  |  do --> GeoIP(ip)  |  do --> SubdomainEnum(d)")
	printSection("HTTP Engine", "http(method, url, opts)  |  httpStatus(r)  |  httpBody(r)")
	printSection("Hacking", "Encode(s,scheme)  Decode(s,scheme)  PayloadGen(type)")
	printSection("Hash", "md5(s)  sha1(s)  sha256(s)  HashIdentify(h)  Crack(h,type)")
	printSection("Crypto", "base64enc(s)  base64dec(s)  CipherSolve(s)")
	printSection("Secrets", "SecretScan(text)")
	printSection("Wordlists", "wordlist(\"admin_paths\")  |  wordlist(\"common_subdomains\")")
	printSection("Payloads", "payloadList(\"xss\")  |  PayloadGen(\"sqli\")")
	printSection("Ports", "hasPort(host, port)  |  portServices()")
	printSection("Mission", "missionStart  missionFind  missionStage  missionReport")
	fmt.Println()

	fmt.Println(colorBold("  STRING HELPERS"))
	fmt.Println()
	printSection("Transform", "upper(s)  lower(s)  trim(s)  reverse(s)  repeat(s,n)")
	printSection("Search", "contains(s,q)  startsWith(s,p)  endsWith(s,p)")
	printSection("Split/Join", "split(s,sep)  join(list,sep)  substr(s,start,end)")
	printSection("Format", "truncate(s,n)  pad(s,n)  str(x)  num(s)  bool(x)")
	printSection("Regex", "regex(pattern,text)  regexMatch(pattern,text)")
	printSection("Crypto", "md5(s)  sha256(s)  base64enc(s)  base64dec(s)")
	fmt.Println()

	fmt.Println(colorBold("  MATH"))
	fmt.Println()
	printSection("Functions", "abs  min  max  floor  ceil  round  sqrt  pow  rand")
	fmt.Println()

	fmt.Println(colorBold("  LISTS"))
	fmt.Println()
	printSection("Functions", "len  append  slice  unique  reverse  sortList  tally")
	printSection("Set ops", "diff(l1,l2)  intersect(l1,l2)  gather(lists)")
	fmt.Println()

	fmt.Println(colorBold("  FILE & SYSTEM"))
	fmt.Println()
	printSection("Files", "readFile(p)  writeFile(p,s)  appendFile(p,s)  exists(p)")
	printSection("JSON", "jsonParse(s)  jsonStr(obj)")
	printSection("Time", "timestamp()  sleep(ms)")
	printSection("IP", "isIP(s)  cidrHosts(cidr)")
	printSection("System", "do --> OSInfo()  |  do --> Run(cmd)")
	fmt.Println()

	fmt.Println(colorBold("  TUI / DISPLAY"))
	fmt.Println()
	printSection("Output", "Trace(x)  print(x)  colorize(s,color)  banner(text)")
	printSection("Tables", "table(headers, rows)")
	printSection("Progress", "progress(current, total, label)")
	printSection("Pipeline", "tally  sortList  diff  intersect  gather  truncate  pad")
	printSection("Input", "Capture(prompt)")
	fmt.Println()

	fmt.Println(colorBold("  GUI  (#Import Spec.GUI)"))
	fmt.Println()
	printSection("Window", "open.window(opts)  end()")
	printSection("Widgets", "GUI.label  GUI.input  GUI.button  GUI.output  GUI.progress")
	printSection("Layouts", "GUI.rowStart/End  GUI.colStart/End  GUI.card/cardEnd")
	printSection("Navigation", "GUI.sidebar  GUI.sidebarEnd  GUI.tabs  GUI.tabPanel")
	printSection("Data", "GUI.table  GUI.appendRow  GUI.clearTable")
	printSection("Extras", "GUI.badge  GUI.alert_box  GUI.code  GUI.spinner")
	printSection("Events", "GUI.on(event, func)  GUI.get(id)  GUI.set(id, val)")
	printSection("Control", "GUI.show  GUI.hide  GUI.enable  GUI.disable  GUI.focus")
	printSection("Runtime", "GUI.setTitle  GUI.setAccent  GUI.setBg  GUI.setProgress")
	printSection("Dialog", "GUI.alert  GUI.confirm  GUI.notify")
	fmt.Println()

	fmt.Println(colorBold("  SPACE PACKAGE MANAGER"))
	fmt.Println()
	printSection("Install", "spectator space get coffee")
	printSection("Verify", "spectator space verify coffee")
	printSection("Hash a file", "spectator space hash mylib.str")
	printSection("Browse", "spectator space registry")
	printSection("Publish", "spectator space make lib = mylib.str")
	fmt.Println()

	fmt.Println(colorBold("  BUILD TARGETS"))
	fmt.Println()
	printBuildPlatforms()

	fmt.Println(colorBold("  EXAMPLES"))
	fmt.Println()
	printCmd("spectator run recon.str", "Run a recon script")
	printCmd("spectator run pentest_gui.str", "Open the GUI pentest dashboard")
	printCmd("spectator build app.str to MyApp.exe for windows", "Build a Windows app")
	printCmd("spectator space get coffee", "Install the Coffee recon library")
	printCmd("spectator space verify coffee", "Verify coffee integrity")
	fmt.Println()

	fmt.Println(colorDim("  Docs & libraries: https://github.com/CzaxStudio/Spectator"))
	fmt.Println()
}

func printReplHelp() {
	fmt.Println()
	fmt.Println(colorBold("  REPL Commands"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 44)))
	printCmd("exit / quit", "Leave the REPL")
	printCmd("clear", "Clear the screen")
	printCmd("help", "Show this help")
	fmt.Println()
	fmt.Println(colorDim("  Tip: multi-line blocks work — just keep typing until { } are balanced."))
	fmt.Println()
}

func printCmd(cmd, desc string) {
	fmt.Printf("  %s%-44s%s %s\n", "\033[33m", cmd, "\033[0m", desc)
}

func printSection(label, value string) {
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", label+":", "\033[0m", value)
}

func printBuildPlatforms() {
	platforms := [][2]string{
		{"windows / win", "Windows 64-bit (.exe)"},
		{"win32", "Windows 32-bit (.exe)"},
		{"linux", "Linux 64-bit"},
		{"linux32", "Linux 32-bit"},
		{"linuxarm", "Linux ARM64 (Raspberry Pi, etc.)"},
		{"mac / macos", "macOS Intel 64-bit"},
		{"macarm / m1", "macOS Apple Silicon"},
		{"freebsd", "FreeBSD 64-bit"},
	}
	for _, p := range platforms {
		fmt.Printf("  %s%-20s%s %s\n", "\033[33m", p[0], "\033[0m", p[1])
	}
	fmt.Println()
}
