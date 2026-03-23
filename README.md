<div align="center">

```
███████╗██████╗ ███████╗ ██████╗████████╗ █████╗ ████████╗ ██████╗ ██████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   ███████║   ██║   ██║   ██║██████╔╝
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║   ██║   ██║   ██║██╔══██╗
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║   ██║   ╚██████╔╝██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

**See Everything. Miss Nothing.**

A cybersecurity scripting language built for pentesters, red teamers, and security researchers.
Write recon scripts, build GUI tools, automate assessments — all in one clean language.

[![License: MIT](https://img.shields.io/badge/License-MIT-00d4aa.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-00d4aa.svg)](releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-00d4aa.svg)](releases)
[![Language](https://img.shields.io/badge/Built%20with-Go-00add8.svg)](https://go.dev)

</div>

---

## What is Spectator?

Spectator is a purpose-built scripting language for cybersecurity work. It combines the simplicity of Python with built-in security modules, a native GUI framework, and a package manager — all compiled into a single standalone binary.

```spectator
## Recon a target in 5 lines
target = "scanme.nmap.org"
ips = resolve(target)
Trace("IPs: " --> join(ips, ", "))
do --> PortScan(target, 1, 1024)
do --> SSLInfo(target)
```

```spectator
## Build a GUI pentest tool
#Import Spec.GUI
open.window({"title": "Ghost Recon", "bg": "#070b14", "accent": "#00d4aa"})
GUI.input("target", "Enter target...")
GUI.button("Scan", "run", {"color": "#00d4aa"})
GUI.output("out", {"height": 400})
GUI.on("run", func() {
  t = GUI.get("target")
  ips = resolve(t)
  each ip : ips { GUI.print("out", "  IP: " --> ip) }
})
end()
```

---

## Features

### Language
- Clean, readable syntax — no semicolons, no boilerplate
- Variables, maps, lists, f-strings, string concatenation (`-->`)
- Functions, recursion, closures, anonymous functions
- `if / elseif / else`, `loop`, `each`, `match`, `try/catch`
- Goroutines via `spawn`, `# runner<?>` shell execution
- Dot notation for maps: `person.name = "Alice"`
- Import libraries: `#Import coffee`

### Built-in Security Modules
| Module | Commands |
|--------|----------|
| **Recon** | `Recon`, `PortScan`, `DNSLookup`, `BannerGrab`, `PingCheck`, `CIDRScan` |
| **OSINT** | `WHOIs`, `GeoIP`, `IPInfo`, `SubdomainEnum`, `SubTakeover` |
| **Web** | `HTTPProbe`, `Headers`, `TechDetect`, `SSLInfo`, `HeaderAudit` |
| **Exploitation** | `CORSTest`, `OpenRedirect`, `SQLiTest`, `CMDInject`, `PathTraversal` |
| **Fuzzing** | `DirBust`, `FuzzURL`, `EmailHarvest` |
| **Payloads** | `PayloadGen(xss/sqli/ssrf/lfi/cmd/ssti/xxe/redirect/nosql/ldap)` |
| **Crypto** | `HashIdentify`, `Crack`, `CipherSolve`, `SecretScan` |
| **Encoding** | `Encode/Decode(url/b64/html/hex/unicode/rot13/double_url)` |
| **Hashing** | `md5`, `sha1`, `sha256`, `base64enc`, `base64dec` |

### HTTP Engine
Full HTTP client built in — sessions, fuzzing, multi-request, extraction:
```spectator
resp = http("GET", "https://target.com", {"timeout": 5000, "follow": true})
Trace(httpStatus(resp))
Trace(httpHeader(resp, "server"))
Trace(extractTitle(httpBody(resp)))
emails = extractEmails(httpBody(resp))
```

### Native GUI Framework (`#Import Spec.GUI`)
Build real desktop security tools — no web framework, no Electron, no Python:

```spectator
open.window({"title": "My Tool", "bg": "#0a0f1a", "accent": "#38bdf8"})
GUI.sidebar([{"id": "scan", "label": "Scanner", "icon": "⌖"}])
GUI.header("Scanner")
GUI.input("target", "Enter target...")
GUI.button("Run", "scan", {"color": "#38bdf8"})
GUI.output("out", {"height": 400})
GUI.on("scan", func() { GUI.print("out", "Scanning " --> GUI.get("target")) })
end()
```

**All GUI widgets:**
`label` · `input` · `password` · `number` · `button` · `iconButton` · `link` · `checkbox` · `toggle` · `radio` · `dropdown` · `slider` · `progress` · `spinner` · `output` · `table` · `image` · `card` · `badge` · `alert_box` · `code` · `tabs` · `sidebar` · `header` · `footer` · `divider` · `space` · `html`

### Mission Engine
Structured pentest pipeline with HTML report generation:
```spectator
m = missionStart("Web App Pentest", "target.com")
missionStage(m, "Recon")
missionFind(m, "CRITICAL", ".env exposed", "Database credentials leaked")
missionFind(m, "HIGH", "Missing HSTS", "SSL stripping possible")
missionEnd(m)
missionReport(m, "report.html")
```

### Space Package Manager
```
Space get coffee            Install a library (SHA-256 verified)
Space get ghost             Install Ghost OSINT library
Space verify coffee         Verify installed file integrity
Space hash mylib.str        Compute SHA-256 of a library file
Space registry              Browse all published libraries
Space make lib = mylib.str  Package and publish your own library
```

Every library install is SHA-256 verified against the central registry — supply-chain attacks blocked by default.

---

## Installation

### Download (No Go required)

Download the pre-built binary for your platform from [Releases](releases):

| Platform | File |
|----------|------|
| Windows 64-bit | `Spectator.exe` |
| Linux 64-bit | `spectator-linux` |
| macOS Intel | `spectator-mac` |
| macOS Apple Silicon | `spectator-mac-arm` |

```powershell
# Windows — run any script
./Spectator.exe run hello.str

# Linux / macOS
chmod +x spectator
./spectator run hello.str
```

### Build from Source

Requires Go 1.22+:

```bash
git clone https://github.com/CzaxStudio/Spectator
cd Spectator

# Build without GUI (pure terminal)
go build -ldflags="-s -w" -o Spectator.exe .

# Build with GUI support (Windows)
go get github.com/jchv/go-webview2
go mod tidy
go build -tags gui -ldflags="-s -w" -o Spectator.exe .

# Build with GUI support (Linux — requires libgtk-3-dev libwebkit2gtk-4.0-dev)
go get github.com/webview/webview_go
go mod tidy
go build -tags gui -ldflags="-s -w" -o spectator .

# Build with GUI support (macOS)
go get github.com/webview/webview_go
go mod tidy
go build -tags gui -ldflags="-s -w" -o spectator .
```

---

## Usage

```
spectator run <file.str>                      Run a script
spectator repl                                Interactive REPL
spectator build <file.str> to <out> for <os> Compile to standalone binary
spectator space <command>                     Package manager
spectator version                             Show version
spectator help                                Full command reference
```

### Build targets
```
windows / win     Windows 64-bit (.exe)
linux             Linux 64-bit
mac / macos       macOS Intel
macarm / m1       macOS Apple Silicon
linuxarm          Linux ARM64 (Raspberry Pi)
win32             Windows 32-bit
freebsd           FreeBSD 64-bit
```

---

## Quick Examples

### DNS Recon
```spectator
target = "example.com"
ips = resolve(target)
mxs = lookupMX(target)
nss = lookupNS(target)
txts = lookupTXT(target)

Trace("[ A  ] " --> join(ips, ", "))
Trace("[ MX ] " --> join(mxs, ", "))
Trace("[ NS ] " --> join(nss, ", "))
each txt : txts { Trace("[ TXT] " --> txt) }
```

### Port Scanner
```spectator
target = Capture("Target: ")
ports  = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]
svcs   = portServices()

each p : ports {
  if hasPort(target, p) {
    Trace("  OPEN  " --> str(p) --> "  " --> svcs[str(p)])
  }
}
```

### Security Header Audit
```spectator
url  = "https://example.com"
resp = http("GET", url, {"timeout": 8000, "follow": true})
hdrs = ["strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "referrer-policy"]

each h : hdrs {
  val = httpHeader(resp, h)
  if val != "" { Trace("[PASS] " --> h) }
  else          { Trace("[FAIL] " --> h --> " missing") }
}
```

### Payload Generator
```spectator
types = ["xss", "sqli", "ssrf", "lfi", "cmd"]
each t : types {
  Trace("── " --> upper(t) --> " ──")
  payloads = payloadList(t)
  each p, idx : payloads {
    if idx < 5 { Trace("  [" --> str(idx+1) --> "] " --> p) }
  }
}
```

### Mission Report
```spectator
m = missionStart("API Security Assessment", "api.target.com")

missionStage(m, "Discovery")
missionFind(m, "INFO", "API v2 detected", "REST API on port 443")
missionNote(m, "Swagger docs found at /api/docs")

missionStage(m, "Vulnerabilities")
missionFind(m, "CRITICAL", "JWT None Algorithm", "Auth bypass via alg:none")
missionFind(m, "HIGH",     "IDOR in /users/{id}", "Access any user account")
missionFind(m, "MEDIUM",   "Rate limiting absent", "Brute force possible")

missionEnd(m)
missionReport(m, "api_assessment.html")
Trace("Report saved.")
```

### Building a Standalone App
```bash
# Creates GhostRecon.exe — no Spectator needed to run it
spectator build ghost_recon.str to GhostRecon.exe for windows

# Cross-compile for Linux from Windows
spectator build scanner.str to scanner for linux
```

---

## Libraries

Install official libraries from the Space registry:

### Coffee — Recon Library
```spectator
#Import coffee
coffee_full("target.com")   ## Full recon: DNS, ports, web, scoring
```

```bash
spectator space get coffee
```

### Ghost — OSINT Library
```spectator
#Import ghost
ghost_domain("target.com")       ## Domain intelligence
ghost_ip("8.8.8.8")             ## IP intelligence + GeoIP
ghost_email("user@target.com")  ## Email OSINT
ghost_username("target_user")   ## Username enumeration across platforms
ghost_full("target.com")        ## All-in-one with mission report
```

```bash
spectator space get ghost
```

### Publishing Your Own Library
```bash
spectator space make lib = mylib.str   # Package + generate registry entry
spectator space hash mylib.str         # Get SHA-256 for registry.json
spectator space publish mylib          # Show how to submit PR
```

---

## Language Reference

### Variables
```spectator
x     = 42
name  = "Spectator"
flag  = true
price = 9.99
let y = "immutable-style declaration"
```

### Strings
```spectator
msg    = "Hello " --> name --> "!"          ## concatenation
fmsg   = f"Hello {name}, you are {age}!"   ## f-string
upper(name)   lower(name)   trim(name)
split(name, ",")   join(list, "-")
contains(name, "spec")   startsWith(name, "Spec")
substr(name, 0, 5)   truncate(name, 20)   pad(name, 30)
replace(name, "old", "new")   reverse(name)   repeat("*", 10)
regex("[0-9]+", text)   regexMatch("^\\d+$", text)
```

### Collections
```spectator
## Lists
tools = ["nmap", "burp", "nikto"]
tools = append(tools, "gobuster")
len(tools)   slice(tools, 0, 2)   unique(tools)
sortList(tools)   reverse(tools)   tally(tools)
diff(l1, l2)   intersect(l1, l2)   gather([l1, l2, l3])

## Maps
info = {"host": "target.com", "port": 443}
info["proto"] = "https"
info.host                    ## dot notation
each val, key : info { }     ## iteration
```

### Control Flow
```spectator
## Conditions
if score >= 90 {
  Trace("A")
} elseif score >= 75 {
  Trace("B")
} else {
  Trace("F")
}

## Match
match status {
  "open"   => { Trace("port open")   }
  "closed" => { Trace("port closed") }
  _        => { Trace("filtered")    }
}

## Loops
loop 10 { Trace(_i) }          ## counted (0-indexed _i)
loop { if done { break } }     ## infinite + break

## Each
each item, idx : list { }
each value, key : map  { }
```

### Functions
```spectator
func scan(host, port) {
  if hasPort(host, port) {
    return "open"
  }
  return "closed"
}

result = scan("target.com", 80)

## Anonymous function
checker = func(x) { return x > 0 }

## Spawn (goroutine)
spawn longScan("target.com")
```

### Error Handling
```spectator
try {
  resp = http("GET", url, {"timeout": 3000})
} catch e {
  Trace("Request failed: " --> e)
}

## Throw custom errors
throw("Target unreachable")
```

### Shell Execution
```spectator
## Capture output
result = # runner<?whoami>
output = # runner<?nmap -sV target.com>

## Pipe commands
open_ports = # runner<?nmap -p- target> | # runner<?grep open>

## Redirect
# runner<?nmap target > /tmp/scan.txt>
```

### File I/O
```spectator
writeFile("output.txt", "scan results")
appendFile("output.txt", "\nmore data")
content = readFile("output.txt")
if exists("output.txt") { Trace("file found") }
```

### JSON
```spectator
obj  = {"target": "example.com", "ports": [80, 443]}
json = jsonStr(obj)
data = jsonParse(json)
Trace(data["target"])
```

---

## GUI Reference

### Window Options
```spectator
open.window({
  "title":     "My Tool",         ## Window title (default: "MyApp")
  "width":     1200,              ## Width in pixels (default: 900)
  "height":    800,               ## Height in pixels (default: 600)
  "bg":        "#070b14",         ## Background color
  "accent":    "#00d4aa",         ## Accent color (buttons, focus, progress)
  "text":      "#e2e8f0",         ## Default text color
  "font":      "Segoe UI",        ## Font family
  "radius":    "8",               ## Border radius in px
  "padding":   "24",              ## Page padding in px
  "resizable": true,              ## Allow window resize
  "scrollbar": true,              ## Show scrollbar
  "css":       ".g-btn { ... }"   ## Inject custom CSS
})
```

### Runtime Commands
```spectator
GUI.get("id")                ## Read widget value
GUI.set("id", "value")       ## Set widget value
GUI.print("out_id", "text")  ## Append line to output box
GUI.clear("id")              ## Clear output or input
GUI.setProgress("bar", 0.75) ## Update progress bar (0.0 to 1.0)
GUI.show("id")               ## Show a hidden widget
GUI.hide("id")               ## Hide a widget
GUI.enable("id")             ## Enable a disabled widget
GUI.disable("id")            ## Disable a widget
GUI.focus("id")              ## Focus an input field
GUI.setTitle("New Title")    ## Change window title
GUI.setAccent("#a855f7")     ## Change accent color live
GUI.setBg("#0f172a")         ## Change background color live
GUI.alert("message")         ## Alert dialog
GUI.confirm("message")       ## Confirm dialog → returns true/false
GUI.notify("title", "body")  ## Desktop notification
GUI.eval("js code")          ## Run raw JavaScript
GUI.css(".sel", "prop", "val") ## Change CSS at runtime
GUI.openTab("tab_id")        ## Switch to a tab
GUI.showSpinner("id")        ## Show loading spinner
GUI.hideSpinner("id")        ## Hide loading spinner
GUI.appendRow("table", row)  ## Add row to table
GUI.clearTable("table")      ## Clear all table rows
```

---

## Platform Support

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Terminal scripts | ✅ | ✅ | ✅ |
| GUI apps | ✅ WebView2 | ✅ WebKitGTK | ✅ WKWebView |
| Standalone builds | ✅ | ✅ | ✅ |
| No runtime needed | ✅ | ✅ | ✅ |
| Cross-compilation (no GUI) | ✅ | ✅ | ✅ |

**GUI dependencies:**
- **Windows** — WebView2 runtime (pre-installed on Windows 10/11)
- **Linux** — `libgtk-3-dev libwebkit2gtk-4.0-dev` (usually pre-installed)
- **macOS** — WKWebView (built into macOS, nothing to install)

End users need **nothing installed**. Spectator binaries are fully self-contained.

---

## Space Package Manager

The Space package manager handles library distribution with cryptographic integrity verification.

```
spectator space get <name>           Install from central registry (SHA-256 verified)
spectator space get <name> <url>     Install from direct URL
spectator space list                 Show installed libraries
spectator space registry             Browse all published libraries
spectator space search <keyword>     Search registry
spectator space info <name>          Full details + update check
spectator space update <name>        Re-download + re-verify
spectator space verify <name>        Verify installed file integrity
spectator space hash <file.str>      Compute SHA-256 of a file
spectator space remove <name>        Uninstall
spectator space make lib = file.str  Package + generate signed registry entry
spectator space publish <name>       Show how to submit to central registry
```

### Publishing a Library

1. Write your library as a `.str` file
2. Host it publicly on GitHub
3. Run `spectator space make lib = mylib.str`
4. Run `spectator space hash mylib.str` — copy the SHA-256
5. Add the generated entry (with hash) to `registry.json` via Pull Request
6. Once merged — anyone on Earth can install with `spectator space get mylib`

---

## Architecture

```
spectator/
├── lexer.go          Tokenizer — converts .str source to token stream
├── parser.go         Parser — builds AST from tokens
├── ast.go            AST node types
├── interpreter.go    Evaluator — executes the AST (177 built-in functions)
├── hacking.go        Security modules — payloads, encoding, hashing, cracking
├── http_engine.go    Full HTTP client — sessions, fuzzing, extraction
├── mission.go        Mission pipeline + HTML report generator
├── runner.go         # runner<?> shell execution engine
├── gui_windows.go    GUI engine for Windows (WebView2)
├── gui_unix.go       GUI engine for Linux/macOS (WebKit)
├── gui_windows_nogui.go  Stub for non-GUI Windows builds
├── gui_other.go      Stub for non-GUI non-Windows builds
├── space.go          Space package manager
├── build.go          Cross-compilation engine
├── main.go           Entry point + REPL
└── colors.go         ANSI color helpers
```

---

## Ethical Use

Spectator is a security research tool. Only use it on systems you own or have **explicit written permission** to test. Unauthorized scanning or exploitation is illegal in most jurisdictions. The authors accept no responsibility for misuse.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

**Publishing a library to the Space registry:**
Open a PR adding your entry to `registry.json`. Include the SHA-256 hash of your hosted `.str` file (compute with `spectator space hash mylib.str`).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built by [CzaxStudio](https://github.com/CzaxStudio)**

*Spectator v2.0.0 — See Everything. Miss Nothing.*

</div>
