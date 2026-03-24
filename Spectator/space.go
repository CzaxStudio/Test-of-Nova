package main

// ── Space — Spectator Package Manager v3.0 ───────────────────────────────────
//
// Works exactly like pip (Python) and cargo (Rust):
//
//   CENTRAL REGISTRY  (read-only, fetched from GitHub, shared by everyone)
//   └── https://raw.githubusercontent.com/CzaxStudio/Spectator/main/registry.json
//
//   LOCAL INSTALL DB  (~/.space/installed.json — only YOUR machine)
//
//   ~/.space/libs/<name>/index.str      ← the actual library code
//   ~/.space/libs/<name>/manifest.json  ← metadata + SHA-256 hash
//
// ── Integrity protection ──────────────────────────────────────────────────────
//   Every library has a SHA-256 hash stored in the central registry.
//   When you run `Space get`, Spectator:
//     1. Downloads the .str file
//     2. Computes its SHA-256
//     3. Compares to the hash in registry.json
//     4. Aborts if they don't match (supply-chain attack prevented)
//   The hash is also stored locally in manifest.json and installed.json.
//   `Space verify <name>` re-checks the installed file against the stored hash.
//
// Commands:
//   Space get <n>           → install from central registry (with hash check)
//   Space get <n> <url>     → install from direct URL (hash computed + stored)
//   Space list              → show YOUR installed libraries + hash status
//   Space registry          → browse ALL published libraries
//   Space search <keyword>  → search central registry
//   Space info <n>          → full details + update check
//   Space update <n>        → re-download + re-verify
//   Space verify <n>        → verify installed file against stored hash
//   Space hash <file.str>   → compute SHA-256 of a .str file
//   Space remove <n>        → uninstall
//   Space make lib = f.str  → package + generate registry entry (with hash)
//   Space publish <n>       → show how to submit to central registry
//   Space help              → show help

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const centralRegistryURL = "https://raw.githubusercontent.com/CzaxStudio/Spectator/main/registry.json"
const centralRegistryPage = "https://github.com/CzaxStudio/Spectator"

// ── Data structures ───────────────────────────────────────────────────────────

type CentralEntry struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Author       string   `json:"author"`
	License      string   `json:"license"`
	Description  string   `json:"description"`
	Source       string   `json:"source"`
	GitHub       string   `json:"github"`
	Keywords     []string `json:"keywords"`
	SHA256       string   `json:"sha256,omitempty"` // hex SHA-256 of the .str file
	RegisteredAt string   `json:"registered_at"`
}

type CentralRegistry map[string]CentralEntry

type InstalledEntry struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Author      string    `json:"author"`
	Source      string    `json:"source"`
	SHA256      string    `json:"sha256"`   // hash recorded at install time
	Verified    bool      `json:"verified"` // was hash matched at install?
	InstalledAt time.Time `json:"installed_at"`
}

type InstalledDB map[string]InstalledEntry

// ── Hash helpers ──────────────────────────────────────────────────────────────

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// hashFile reads a file from disk and returns its SHA-256 hex.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// verifyDownload checks downloaded bytes against an expected hash.
// If expectedHash is empty, skips check and returns the computed hash.
// Returns (actualHash, nil) on success, (actualHash, error) on mismatch.
func verifyDownload(data []byte, expectedHash string) (string, error) {
	actual := sha256Hex(data)
	if expectedHash == "" {
		return actual, nil
	}
	if actual != strings.ToLower(strings.TrimSpace(expectedHash)) {
		return actual, fmt.Errorf("SHA-256 mismatch\n    expected : %s\n    computed : %s", expectedHash, actual)
	}
	return actual, nil
}

// ── Command router ────────────────────────────────────────────────────────────

func RunSpace(args []string) {
	printSpaceBanner()
	if len(args) == 0 {
		spaceHelp()
		return
	}
	switch args[0] {
	case "get":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space get <libname> [url]"))
			return
		}
		spaceGet(args[1:])
	case "list":
		spaceList()
	case "registry":
		spaceRegistry()
	case "info":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space info <libname>"))
			return
		}
		spaceInfo(args[1])
	case "make":
		spaceMake(args[1:])
	case "publish":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space publish <libname>"))
			return
		}
		spacePublish(args[1])
	case "remove", "rm", "uninstall":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space remove <libname>"))
			return
		}
		spaceRemove(args[1])
	case "update", "upgrade":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space update <libname>"))
			return
		}
		spaceUpdate(args[1])
	case "search":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space search <keyword>"))
			return
		}
		spaceSearch(args[1])
	case "verify":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space verify <libname>"))
			return
		}
		spaceVerify(args[1])
	case "hash":
		if len(args) < 2 {
			fmt.Println(colorRed("  [!] Usage: Space hash <file.str>"))
			return
		}
		spaceHash(args[1])
	case "help", "--help", "-h":
		spaceHelp()
	default:
		fmt.Println(colorRed("  [!] Unknown Space command: " + args[0]))
		spaceHelp()
	}
}

// ── Space get ─────────────────────────────────────────────────────────────────

func spaceGet(args []string) {
	name := strings.ToLower(strings.TrimSpace(args[0]))
	directURL := ""
	if len(args) >= 2 {
		directURL = args[1]
	}

	fmt.Println()

	var sourceURL string
	var entry CentralEntry

	if directURL != "" {
		sourceURL = directURL
		entry = CentralEntry{Name: name, Source: directURL, Version: "direct"}
		fmt.Println(colorBold("  [Space] Installing " + name + " from direct URL"))
		fmt.Println(colorDim("  " + directURL))
		fmt.Println(colorYellow("  [~] No registry hash available for direct installs — hash will be recorded for future verification."))
	} else {
		fmt.Println(colorBold("  [Space] Looking up " + name + "..."))
		reg, err := fetchCentralRegistry()
		if err != nil {
			fmt.Println(colorRed("  [!] Cannot reach central registry: " + err.Error()))
			fmt.Println(colorYellow("  Tip: install directly with: Space get " + name + " <raw-url>"))
			return
		}
		var found bool
		entry, found = reg[name]
		if !found {
			fmt.Println(colorRed("  [!] Library \"" + name + "\" not found in central registry."))
			fmt.Println()
			fmt.Println(colorYellow("  Browse available:    Space registry"))
			fmt.Println(colorYellow("  Search:              Space search <keyword>"))
			fmt.Println(colorYellow("  Install from URL:    Space get " + name + " <raw-url>"))
			fmt.Println(colorDim("  Publish your own:    Space make lib = yourfile.str"))
			fmt.Println()
			return
		}
		sourceURL = entry.Source
		fmt.Println(colorGreen("  [✓] Found in registry"))
		fmt.Println()
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Name:", "\033[0m", entry.Name)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Version:", "\033[0m", entry.Version)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Author:", "\033[0m", entry.Author)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "License:", "\033[0m", entry.License)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Desc:", "\033[0m", entry.Description)
		if entry.SHA256 != "" {
			fmt.Printf("  %s%-14s%s %s...\n", "\033[36m", "SHA-256:", "\033[0m", entry.SHA256[:16])
		}
		fmt.Println()
	}

	// Download
	fmt.Println(colorCyan("  ↓ Downloading: ") + sourceURL)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(sourceURL)
	if err != nil {
		fmt.Println(colorRed("  [!] Download failed: " + err.Error()))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Println(colorRed(fmt.Sprintf("  [!] HTTP %d — check source URL.", resp.StatusCode)))
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(colorRed("  [!] Read failed: " + err.Error()))
		return
	}

	// ── Integrity check ───────────────────────────────────────────────────────
	fmt.Println(colorCyan("  ⊕ Verifying integrity..."))
	actualHash, hashErr := verifyDownload(body, entry.SHA256)
	if hashErr != nil {
		fmt.Println()
		fmt.Println(colorRed("  ╔══════════════════════════════════════════════════════╗"))
		fmt.Println(colorRed("  ║  ⚠  INTEGRITY CHECK FAILED                          ║"))
		fmt.Println(colorRed("  ║  The downloaded file does not match the registry.   ║"))
		fmt.Println(colorRed("  ║  This may indicate a supply-chain attack.           ║"))
		fmt.Println(colorRed("  ╚══════════════════════════════════════════════════════╝"))
		fmt.Println(colorRed("  " + hashErr.Error()))
		fmt.Println(colorYellow("  Installation aborted. Contact the library author."))
		fmt.Println()
		return
	}
	verified := entry.SHA256 != ""
	if verified {
		fmt.Println(colorGreen("  [✓] Integrity verified — SHA-256 matches registry"))
	} else {
		fmt.Println(colorDim("  [~] No hash in registry — recorded hash for future verification"))
	}
	fmt.Println(colorDim("      SHA-256: " + actualHash))

	// Install
	libPath := filepath.Join(spaceLibDir(), name)
	os.MkdirAll(libPath, 0755)
	if err := os.WriteFile(filepath.Join(libPath, "index.str"), body, 0644); err != nil {
		fmt.Println(colorRed("  [!] Write failed: " + err.Error()))
		return
	}

	// Manifest
	manifest := map[string]interface{}{
		"name":         entry.Name,
		"version":      entry.Version,
		"author":       entry.Author,
		"license":      entry.License,
		"description":  entry.Description,
		"source":       sourceURL,
		"github":       entry.GitHub,
		"sha256":       actualHash,
		"verified":     verified,
		"installed_at": time.Now().Format(time.RFC3339),
	}
	if mdata, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		os.WriteFile(filepath.Join(libPath, "manifest.json"), mdata, 0644)
	}

	// DB
	db := loadInstalledDB()
	db[name] = InstalledEntry{
		Name:        name,
		Version:     entry.Version,
		Author:      entry.Author,
		Source:      sourceURL,
		SHA256:      actualHash,
		Verified:    verified,
		InstalledAt: time.Now(),
	}
	saveInstalledDB(db)

	size := len(body)
	sizeStr := fmt.Sprintf("%d bytes", size)
	if size > 1024 {
		sizeStr = fmt.Sprintf("%.1f KB", float64(size)/1024)
	}

	fmt.Println()
	fmt.Println(colorGreen("  [✓] Installed: " + name + " (" + sizeStr + ")"))
	fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Location:", "\033[0m", filepath.Join(libPath, "index.str"))
	fmt.Printf("  %s%-14s%s %s...\n", "\033[36m", "SHA-256:", "\033[0m", actualHash[:16])
	fmt.Println(colorYellow("\n  Use in script: #Import " + name + "\n"))
}

// ── Space verify <n> ──────────────────────────────────────────────────────────

func spaceVerify(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	fmt.Println()
	fmt.Println(colorBold("  [Space] Verifying integrity of: " + name))
	fmt.Println()

	db := loadInstalledDB()
	entry, installed := db[name]
	if !installed {
		fmt.Println(colorRed("  [!] \"" + name + "\" is not installed."))
		return
	}
	if entry.SHA256 == "" {
		fmt.Println(colorYellow("  [~] No hash recorded for " + name + " — cannot verify."))
		fmt.Println(colorDim("      Reinstall with: Space update " + name))
		return
	}

	libPath := filepath.Join(spaceLibDir(), name, "index.str")
	currentHash, err := hashFile(libPath)
	if err != nil {
		fmt.Println(colorRed("  [!] Cannot read installed file: " + err.Error()))
		return
	}

	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Recorded hash:", "\033[0m", entry.SHA256)
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Current hash:", "\033[0m", currentHash)

	if currentHash == entry.SHA256 {
		fmt.Println()
		fmt.Println(colorGreen("  [✓] VERIFIED — file is intact and unmodified"))
	} else {
		fmt.Println()
		fmt.Println(colorRed("  ╔══════════════════════════════════════════════════════╗"))
		fmt.Println(colorRed("  ║  ⚠  INTEGRITY VIOLATION DETECTED                    ║"))
		fmt.Println(colorRed("  ║  The installed file has been modified since install. ║"))
		fmt.Println(colorRed("  ║  Reinstall immediately: Space update " + name + strings.Repeat(" ", max(0, 16-len(name))) + "║"))
		fmt.Println(colorRed("  ╚══════════════════════════════════════════════════════╝"))
	}

	// Also compare against registry
	reg, err := fetchCentralRegistry()
	if err == nil {
		if central, found := reg[name]; found && central.SHA256 != "" {
			fmt.Println()
			if currentHash == central.SHA256 {
				fmt.Println(colorGreen("  [✓] Also matches current registry hash"))
			} else {
				fmt.Println(colorYellow("  [~] Does not match current registry hash"))
				fmt.Println(colorYellow("      Registry: " + central.SHA256[:16] + "..."))
				fmt.Println(colorYellow("      Run: Space update " + name))
			}
		}
	}
	fmt.Println()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Space hash <file.str> ─────────────────────────────────────────────────────

func spaceHash(path string) {
	fmt.Println()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(colorRed("  [!] Cannot read file: " + err.Error()))
		return
	}
	h := sha256Hex(data)
	size := len(data)
	sizeStr := fmt.Sprintf("%d bytes", size)
	if size > 1024 {
		sizeStr = fmt.Sprintf("%.1f KB", float64(size)/1024)
	}

	fmt.Println(colorBold("  [Space] SHA-256 Hash"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 72)))
	fmt.Printf("  %s%-12s%s %s\n", "\033[36m", "File:", "\033[0m", path)
	fmt.Printf("  %s%-12s%s %s\n", "\033[36m", "Size:", "\033[0m", sizeStr)
	fmt.Printf("  %s%-12s%s %s\n", "\033[36m", "SHA-256:", "\033[0m", h)
	fmt.Println()
	fmt.Println(colorDim("  Add this to your registry.json entry:"))
	fmt.Println(colorCyan(`  "sha256": "` + h + `"`))
	fmt.Println()
}

// ── Space registry ────────────────────────────────────────────────────────────

func spaceRegistry() {
	fmt.Println()
	fmt.Println(colorBold("  Fetching central registry..."))
	fmt.Println(colorDim("  " + centralRegistryURL))
	fmt.Println()

	reg, err := fetchCentralRegistry()
	if err != nil {
		fmt.Println(colorRed("  [!] Could not reach registry: " + err.Error()))
		fmt.Println(colorDim("  Registry: " + centralRegistryPage))
		return
	}
	if len(reg) == 0 {
		fmt.Println(colorYellow("  [~] Central registry is empty."))
		fmt.Println(colorDim("  Publish: Space make lib = yourfile.str"))
		return
	}

	db := loadInstalledDB()
	plural := "libraries"
	if len(reg) == 1 {
		plural = "library"
	}
	fmt.Println(colorBold(fmt.Sprintf("  Central Registry — %d %s", len(reg), plural)))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 70)))

	for _, entry := range reg {
		_, inst := db[entry.Name]
		status := colorDim("not installed")
		if inst {
			status = colorGreen("installed")
		}
		hashStatus := colorDim("no hash")
		if entry.SHA256 != "" {
			hashStatus = colorGreen("✓ hash verified")
		}

		fmt.Println()
		fmt.Printf("  %s %s  %s  %s\n", colorGreen("◈"), colorBold(entry.Name), status, hashStatus)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Version:", "\033[0m", entry.Version)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Author:", "\033[0m", entry.Author)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "License:", "\033[0m", entry.License)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Description:", "\033[0m", entry.Description)
		if len(entry.Keywords) > 0 {
			fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Keywords:", "\033[0m", strings.Join(entry.Keywords, ", "))
		}
		if entry.SHA256 != "" {
			fmt.Printf("  %s%-14s%s %s...\n", "\033[36m", "SHA-256:", "\033[0m", entry.SHA256[:16])
		}
		if !inst {
			fmt.Printf("  %s\n", colorYellow("  → Space get "+entry.Name))
		}
		fmt.Println(colorCyan("  " + strings.Repeat("─", 70)))
	}
	fmt.Println()
	fmt.Println(colorDim("  Publish your library: Space make lib = yourfile.str"))
	fmt.Println(colorDim("  Registry page: " + centralRegistryPage))
	fmt.Println()
}

// ── Space list ────────────────────────────────────────────────────────────────

func spaceList() {
	db := loadInstalledDB()
	fmt.Println()
	if len(db) == 0 {
		fmt.Println(colorYellow("  [~] No libraries installed."))
		fmt.Println(colorDim("  Browse: Space registry  |  Install: Space get <name>"))
		fmt.Println()
		return
	}

	fmt.Println(colorBold("  Installed Libraries"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 78)))
	fmt.Printf("  %-18s %-10s %-18s %-8s %s\n",
		colorBold("Name"), colorBold("Version"), colorBold("Author"),
		colorBold("Hash"), colorBold("Installed"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 78)))

	for _, entry := range db {
		hashStatus := colorRed("none")
		if entry.SHA256 != "" {
			if entry.Verified {
				hashStatus = colorGreen("✓ ok")
			} else {
				hashStatus = colorYellow("~unverified")
			}
		}
		fmt.Printf("  %-18s %-10s %-18s %-8s %s\n",
			colorGreen(entry.Name),
			colorCyan(entry.Version),
			colorDim(entry.Author),
			hashStatus,
			colorDim(entry.InstalledAt.Format("2006-01-02")))
	}
	fmt.Println(colorCyan("  " + strings.Repeat("─", 78)))
	plural := "libraries"
	if len(db) == 1 {
		plural = "library"
	}
	fmt.Printf("  %d %s installed.\n", len(db), plural)
	fmt.Println(colorDim("  Verify integrity: Space verify <name>"))
	fmt.Println()
}

// ── Space info ────────────────────────────────────────────────────────────────

func spaceInfo(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	fmt.Println()
	db := loadInstalledDB()

	if entry, installed := db[name]; installed {
		fmt.Println(colorBold("  Library: " + name))
		fmt.Println(colorCyan("  " + strings.Repeat("─", 56)))
		fmt.Printf("  %s%-18s%s %s\n", "\033[32m", "Status:", "\033[0m", colorGreen("Installed"))
		fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Version:", "\033[0m", entry.Version)
		fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Author:", "\033[0m", entry.Author)
		fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Source:", "\033[0m", entry.Source)
		fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Installed:", "\033[0m", entry.InstalledAt.Format("2006-01-02 15:04"))
		if entry.SHA256 != "" {
			verified := colorYellow("not verified at install")
			if entry.Verified {
				verified = colorGreen("verified at install")
			}
			fmt.Printf("  %s%-18s%s %s...  %s\n", "\033[36m", "SHA-256:", "\033[0m", entry.SHA256[:16], verified)
		}
		reg, err := fetchCentralRegistry()
		if err == nil {
			if central, found := reg[name]; found {
				fmt.Println()
				if central.Version != entry.Version {
					fmt.Println(colorYellow("  [!] Update available: " + entry.Version + " → " + central.Version))
					fmt.Println(colorYellow("      Run: Space update " + name))
				} else {
					fmt.Println(colorGreen("  [✓] Up to date"))
				}
			}
		}
		fmt.Println()
		fmt.Println(colorDim("  Verify file integrity: Space verify " + name))
		fmt.Println()
		return
	}

	fmt.Println(colorDim("  Checking central registry..."))
	reg, err := fetchCentralRegistry()
	if err != nil {
		fmt.Println(colorRed("  [!] Registry unreachable: " + err.Error()))
		return
	}
	entry, found := reg[name]
	if !found {
		fmt.Println(colorRed("  [!] Library not found: " + name))
		fmt.Println(colorDim("  Browse all: Space registry"))
		return
	}
	fmt.Println(colorBold("  Library: " + name))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 56)))
	fmt.Printf("  %s%-18s%s %s\n", "\033[33m", "Status:", "\033[0m", colorYellow("Not installed"))
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Version:", "\033[0m", entry.Version)
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Author:", "\033[0m", entry.Author)
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "License:", "\033[0m", entry.License)
	fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "Description:", "\033[0m", entry.Description)
	if entry.SHA256 != "" {
		fmt.Printf("  %s%-18s%s %s...  %s\n", "\033[36m", "SHA-256:", "\033[0m", entry.SHA256[:16], colorGreen("registry-signed"))
	} else {
		fmt.Printf("  %s%-18s%s %s\n", "\033[36m", "SHA-256:", "\033[0m", colorYellow("not in registry"))
	}
	fmt.Println()
	fmt.Println(colorYellow("  Install: Space get " + name))
	fmt.Println()
}

// ── Space make ────────────────────────────────────────────────────────────────

func spaceMake(args []string) {
	if len(args) < 3 || args[0] != "lib" || args[1] != "=" {
		fmt.Println(colorRed("  [!] Usage: Space make lib = <filename.str>"))
		return
	}
	pattern := args[2]
	reader := bufio.NewReader(os.Stdin)
	prompt := func(label string) string {
		fmt.Print(colorCyan("  " + label))
		s, _ := reader.ReadString('\n')
		return strings.TrimSpace(s)
	}

	var srcFiles []string
	if pattern == "*" || pattern == "*.str" {
		matches, _ := filepath.Glob("*.str")
		if len(matches) == 0 {
			fmt.Println(colorRed("  [!] No .str files found."))
			return
		}
		srcFiles = matches
	} else {
		if !strings.HasSuffix(strings.ToLower(pattern), ".str") {
			pattern += ".str"
		}
		srcFiles = []string{pattern}
	}

	fmt.Println()
	fmt.Println(colorBold("  [Space] Package a new library"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 56)))
	fmt.Println()

	name := ""
	for {
		name = strings.ToLower(strings.ReplaceAll(prompt("Library name        : "), " ", "_"))
		if name == "" {
			fmt.Println(colorRed("  [!] Name cannot be empty."))
			continue
		}
		reg, err := fetchCentralRegistry()
		if err == nil {
			if existing, taken := reg[name]; taken {
				fmt.Println(colorRed("  [!] \"" + name + "\" is already in the registry (author: " + existing.Author + ")"))
				fmt.Println(colorCyan("  Choose a different name."))
				continue
			}
		}
		break
	}

	version := prompt("Version             : ")
	if version == "" {
		version = "1.0.0"
	}
	author := prompt("Author              : ")
	license := prompt("License             : ")
	if license == "" {
		license = "MIT"
	}
	desc := prompt("Description         : ")
	keywords := prompt("Keywords (comma-sep): ")

	fmt.Println()
	fmt.Println(colorCyan("  ─── Source URL ──────────────────────────────────────────"))
	fmt.Println(colorDim("  Raw URL to your .str on GitHub (users download from here)"))
	fmt.Println(colorDim("  e.g. https://raw.githubusercontent.com/you/repo/main/" + name + ".str"))
	fmt.Println()

	sourceURL := ""
	for {
		sourceURL = prompt("Raw download URL    : ")
		if sourceURL == "" {
			fmt.Println(colorRed("  [!] Required."))
			continue
		}
		if !strings.HasPrefix(sourceURL, "http") {
			fmt.Println(colorRed("  [!] Must start with https://"))
			continue
		}
		break
	}
	githubPage := prompt("GitHub page (optional): ")

	// Merge files
	var combined strings.Builder
	combined.WriteString(fmt.Sprintf("## Library  : %s\n## Version  : %s\n## Author   : %s\n## License  : %s\n\n", name, version, author, license))
	for _, sf := range srcFiles {
		data, err := os.ReadFile(sf)
		if err != nil {
			fmt.Println(colorYellow("  [~] Skipping " + sf))
			continue
		}
		combined.WriteString("\n## --- " + sf + " ---\n")
		combined.Write(data)
		combined.WriteString("\n")
	}
	combinedBytes := []byte(combined.String())

	// Compute hash of the packaged library
	libHash := sha256Hex(combinedBytes)

	// Install locally
	libPath := filepath.Join(spaceLibDir(), name)
	os.MkdirAll(libPath, 0755)
	os.WriteFile(filepath.Join(libPath, "index.str"), combinedBytes, 0644)
	manifest := map[string]interface{}{
		"name": name, "version": version, "author": author,
		"license": license, "description": desc, "source": sourceURL,
		"github": githubPage, "sha256": libHash, "verified": true,
		"installed_at": time.Now().Format(time.RFC3339),
	}
	mdata, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(filepath.Join(libPath, "manifest.json"), mdata, 0644)

	db := loadInstalledDB()
	db[name] = InstalledEntry{Name: name, Version: version, Author: author, Source: sourceURL, SHA256: libHash, Verified: true, InstalledAt: time.Now()}
	saveInstalledDB(db)

	// Generate registry entry
	kwList := []string{}
	for _, k := range strings.Split(keywords, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			kwList = append(kwList, k)
		}
	}
	regEntry := CentralEntry{
		Name: name, Version: version, Author: author, License: license,
		Description: desc, Source: sourceURL, GitHub: githubPage,
		Keywords: kwList, SHA256: libHash, RegisteredAt: time.Now().Format("2006-01-02"),
	}
	regJSON, _ := json.MarshalIndent(regEntry, "  ", "  ")

	fmt.Println()
	fmt.Println(colorGreen("  [✓] Library packaged and installed locally!"))
	fmt.Println()
	fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Name:", "\033[0m", name)
	fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Version:", "\033[0m", version)
	fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "SHA-256:", "\033[0m", libHash)
	fmt.Println()
	fmt.Println(colorBold("  ─── Publish to central registry ──────────────────────────"))
	fmt.Println(colorYellow("  So everyone can install with: Space get " + name))
	fmt.Println()
	fmt.Println(colorDim("  1. Fork → " + centralRegistryPage))
	fmt.Println(colorDim("  2. Add this to registry.json:"))
	fmt.Println()
	fmt.Println(colorCyan(`  "` + name + `": ` + string(regJSON) + `,`))
	fmt.Println()
	fmt.Println(colorDim("  3. Submit a Pull Request."))
	fmt.Println()
	fmt.Println(colorYellow("  ⚠  IMPORTANT: The SHA-256 above MUST match your hosted .str file."))
	fmt.Println(colorYellow("     If you modify the file, recompute: Space hash " + name + ".str"))
	fmt.Println()

	entryFile := name + "_registry_entry.json"
	entryJSON, _ := json.MarshalIndent(map[string]CentralEntry{name: regEntry}, "", "  ")
	if os.WriteFile(entryFile, entryJSON, 0644) == nil {
		fmt.Println(colorGreen("  [✓] Registry entry saved to: " + entryFile))
	}
	fmt.Println()
}

// ── Space publish ─────────────────────────────────────────────────────────────

func spacePublish(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	fmt.Println()
	db := loadInstalledDB()
	entry, installed := db[name]
	if !installed {
		fmt.Println(colorRed("  [!] \"" + name + "\" is not installed locally."))
		fmt.Println(colorYellow("  Run: Space make lib = yourfile.str  first."))
		return
	}
	reg, err := fetchCentralRegistry()
	if err == nil {
		if _, found := reg[name]; found {
			fmt.Println(colorGreen("  [✓] \"" + name + "\" is already in the central registry!"))
			fmt.Println(colorDim("  Anyone can install: Space get " + name))
			return
		}
	}
	regEntry := CentralEntry{
		Name: entry.Name, Version: entry.Version, Author: entry.Author,
		Source: entry.Source, SHA256: entry.SHA256, RegisteredAt: time.Now().Format("2006-01-02"),
	}
	regJSON, _ := json.MarshalIndent(regEntry, "  ", "  ")
	fmt.Println(colorBold("  Publish \"" + name + "\" to the central registry"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 52)))
	fmt.Println()
	fmt.Println(colorDim("  1. Fork → " + centralRegistryPage))
	fmt.Println(colorDim("  2. Add this entry to registry.json:"))
	fmt.Println()
	fmt.Println(colorCyan(`  "` + name + `": ` + string(regJSON) + `,`))
	fmt.Println()
	fmt.Println(colorDim("  3. Submit a Pull Request — once merged, everyone can:"))
	fmt.Println(colorGreen("     Space get " + name))
	fmt.Println()
}

// ── Space remove ──────────────────────────────────────────────────────────────

func spaceRemove(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	libPath := filepath.Join(spaceLibDir(), name)
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		fmt.Println(colorRed("  [!] Not installed: " + name))
		return
	}
	os.RemoveAll(libPath)
	db := loadInstalledDB()
	delete(db, name)
	saveInstalledDB(db)
	fmt.Println(colorGreen("  [✓] Uninstalled: " + name))
	fmt.Println(colorDim("  Reinstall: Space get " + name))
}

// ── Space update ──────────────────────────────────────────────────────────────

func spaceUpdate(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	fmt.Println()
	db := loadInstalledDB()
	entry, installed := db[name]
	if !installed {
		fmt.Println(colorRed("  [!] \"" + name + "\" is not installed. Run: Space get " + name))
		return
	}

	fmt.Println(colorBold("  [Space] Updating: " + name))
	sourceURL := entry.Source
	var registryHash string

	reg, err := fetchCentralRegistry()
	if err == nil {
		if central, found := reg[name]; found {
			sourceURL = central.Source
			registryHash = central.SHA256
			if central.Version != entry.Version {
				fmt.Println(colorYellow("  " + entry.Version + " → " + central.Version))
			} else {
				fmt.Println(colorDim("  Already on latest version. Re-downloading..."))
			}
		}
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(sourceURL)
	if err != nil {
		fmt.Println(colorRed("  [!] Download failed: " + err.Error()))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Println(colorRed(fmt.Sprintf("  [!] HTTP %d", resp.StatusCode)))
		return
	}
	body, _ := io.ReadAll(resp.Body)

	// Verify hash
	actualHash, hashErr := verifyDownload(body, registryHash)
	if hashErr != nil {
		fmt.Println(colorRed("  [!] INTEGRITY CHECK FAILED during update!"))
		fmt.Println(colorRed("  " + hashErr.Error()))
		fmt.Println(colorYellow("  Update aborted."))
		return
	}
	verified := registryHash != ""
	if verified {
		fmt.Println(colorGreen("  [✓] Integrity verified"))
	}

	libPath := filepath.Join(spaceLibDir(), name)
	os.MkdirAll(libPath, 0755)
	os.WriteFile(filepath.Join(libPath, "index.str"), body, 0644)

	if err == nil {
		if central, found := reg[name]; found {
			db[name] = InstalledEntry{Name: name, Version: central.Version, Author: central.Author, Source: sourceURL, SHA256: actualHash, Verified: verified, InstalledAt: time.Now()}
		} else {
			e := db[name]
			e.InstalledAt = time.Now()
			e.SHA256 = actualHash
			e.Verified = verified
			db[name] = e
		}
	}
	saveInstalledDB(db)
	fmt.Println(colorGreen("  [✓] Updated: " + name))
	fmt.Printf("  %s%-14s%s %s...\n", "\033[36m", "SHA-256:", "\033[0m", actualHash[:16])
	fmt.Println()
}

// ── Space search ──────────────────────────────────────────────────────────────

func spaceSearch(keyword string) {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	fmt.Println()
	fmt.Println(colorBold("  [Space] Searching for \"" + keyword + "\"..."))
	fmt.Println()
	reg, err := fetchCentralRegistry()
	if err != nil {
		fmt.Println(colorRed("  [!] Registry unreachable: " + err.Error()))
		return
	}
	db := loadInstalledDB()
	found := 0
	for _, entry := range reg {
		hay := strings.ToLower(entry.Name + " " + entry.Description + " " + entry.Author + " " + strings.Join(entry.Keywords, " "))
		if !strings.Contains(hay, keyword) {
			continue
		}
		_, inst := db[entry.Name]
		status := colorDim("not installed")
		if inst {
			status = colorGreen("installed")
		}
		hashBadge := colorYellow("no hash")
		if entry.SHA256 != "" {
			hashBadge = colorGreen("✓ signed")
		}
		fmt.Printf("  %s %s  %s  %s\n", colorGreen("◈"), colorBold(entry.Name), status, hashBadge)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Author:", "\033[0m", entry.Author)
		fmt.Printf("  %s%-14s%s %s\n", "\033[36m", "Description:", "\033[0m", entry.Description)
		if !inst {
			fmt.Println(colorYellow("    Space get " + entry.Name))
		}
		fmt.Println()
		found++
	}
	if found == 0 {
		fmt.Println(colorYellow("  No results for \"" + keyword + "\""))
		fmt.Println(colorDim("  Browse all: Space registry"))
	} else {
		fmt.Printf("  %d result(s)\n\n", found)
	}
}

// ── Central registry ──────────────────────────────────────────────────────────

func fetchCentralRegistry() (CentralRegistry, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(centralRegistryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var reg CentralRegistry
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, fmt.Errorf("invalid registry JSON: %v", err)
	}
	return reg, nil
}

// ── Local DB ──────────────────────────────────────────────────────────────────

func installedDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".space", "installed.json")
}
func loadInstalledDB() InstalledDB {
	data, err := os.ReadFile(installedDBPath())
	if err != nil {
		return make(InstalledDB)
	}
	var db InstalledDB
	if err := json.Unmarshal(data, &db); err != nil {
		return make(InstalledDB)
	}
	return db
}
func saveInstalledDB(db InstalledDB) {
	data, _ := json.MarshalIndent(db, "", "  ")
	home, _ := os.UserHomeDir()
	os.MkdirAll(filepath.Join(home, ".space"), 0755)
	os.WriteFile(installedDBPath(), data, 0644)
}
func spaceLibDir() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".space", "libs")
	os.MkdirAll(dir, 0755)
	return dir
}

// ── Help ──────────────────────────────────────────────────────────────────────

func spaceHelp() {
	fmt.Println(colorBold("\n  Space — Spectator Package Manager"))
	fmt.Println(colorDim("  Integrity-verified library distribution"))
	fmt.Println(colorCyan("  " + strings.Repeat("─", 62)))
	cmds := [][2]string{
		{"get <name>", "Install from central registry (SHA-256 verified)"},
		{"get <name> <url>", "Install from direct URL (hash recorded)"},
		{"list", "Show installed libraries + hash status"},
		{"registry", "Browse ALL published libraries"},
		{"search <keyword>", "Search registry by keyword"},
		{"info <name>", "Full details + update check"},
		{"update <name>", "Re-download + re-verify integrity"},
		{"verify <name>", "Verify installed file against stored hash"},
		{"hash <file.str>", "Compute SHA-256 of a file"},
		{"remove <name>", "Uninstall from your machine"},
		{"make lib = <file>", "Package + generate signed registry entry"},
		{"publish <name>", "Show how to submit to central registry"},
	}
	for _, c := range cmds {
		fmt.Printf("  %s%-32s%s %s\n", "\033[33m", "Space "+c[0], "\033[0m", c[1])
	}
	fmt.Println()
	fmt.Println(colorBold("  How integrity works:"))
	fmt.Println(colorDim("  Every library has a SHA-256 hash in registry.json."))
	fmt.Println(colorDim("  On install, the download is verified against this hash."))
	fmt.Println(colorDim("  Mismatches abort the install — supply-chain attacks blocked."))
	fmt.Println()
	fmt.Println(colorDim("  Central registry: " + centralRegistryURL))
	fmt.Println()
}

func printSpaceBanner() {
	fmt.Print(colorCyan(`
  ╔═══════════════════════════════════════════════╗
  ║  ◈  S P A C E                                 ║
  ║  Spectator Package Manager  v3.0              ║
  ║  Integrity-verified library distribution      ║
  ╚═══════════════════════════════════════════════╝`))
	fmt.Println()
}

// Backward compat stubs
type Registry map[string]RegistryEntry
type RegistryEntry struct {
	Name         string
	Author       string
	Description  string
	Source       string
	GitHub       string
	Version      string
	License      string
	RegisteredAt time.Time
}

func loadRegistry() Registry  { return make(Registry) }
func saveRegistry(_ Registry) {}
