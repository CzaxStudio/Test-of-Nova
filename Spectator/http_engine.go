package main

// ── Spectator Full HTTP Engine ────────────────────────────────────────────────
//
// Adds these builtins to Spectator:
//
//   http(method, url, opts)           → response map
//   httpSession()                     → session handle (string key)
//   httpSessionSet(s, key, val)       → configure session
//   httpSessionGet(s, url, opts)      → GET with session
//   httpSessionPost(s, url, body, opts) → POST with session
//   httpSessionClose(s)               → destroy session
//   httpDo(s, method, url, opts)      → any method with session
//   httpBrute(url, field, wordlist, opts) → credential bruteforce
//   httpFuzz(url, marker, wordlist, opts) → parameter fuzzing
//   httpHeaders(resp)                 → get headers from response
//   httpBody(resp)                    → get body from response
//   httpStatus(resp)                  → get status code from response
//   httpCookies(resp)                 → get cookies from response
//   httpEncode(s)                     → URL-encode a string (alias)
//   parseHTML(html, selector)         → extract text matching CSS-like selector
//   extractLinks(html, base)          → extract all href links
//   extractForms(html)                → extract form fields
//   rateLimit(n, ms)                  → rate limiter token bucket
//
// The response map returned by http() contains:
//   resp["status"]   → int    (200, 404, ...)
//   resp["body"]     → string (full response body)
//   resp["headers"]  → map    (header name → value)
//   resp["cookies"]  → map    (cookie name → value)
//   resp["url"]      → string (final URL after redirects)
//   resp["length"]   → int    (body byte length)
//   resp["time"]     → int    (response time in milliseconds)
//
// opts is an optional map argument:
//   opts["headers"]  → map of extra request headers
//   opts["cookies"]  → map of cookies to send
//   opts["auth"]     → "user:pass" (Basic auth)
//   opts["token"]    → "Bearer xyz" (Authorization header)
//   opts["timeout"]  → int milliseconds (default 10000)
//   opts["follow"]   → bool (follow redirects, default true)
//   opts["verify"]   → bool (verify TLS, default true)
//   opts["proxy"]    → "http://127.0.0.1:8080"
//   opts["body"]     → string (request body)
//   opts["type"]     → content-type (default "application/x-www-form-urlencoded")
//   opts["maxbody"]  → int max bytes to read from body (default 2MB)
//   opts["agent"]    → custom User-Agent string

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"os"
)

// ── Session store ──────────────────────────────────────────────────────────────

type HTTPSession struct {
	client  *http.Client
	jar     *cookiejar.Jar
	headers map[string]string // default headers for every request
	mu      sync.Mutex
}

var (
	sessionStore   = map[string]*HTTPSession{}
	sessionStoreMu sync.Mutex
	sessionCounter int64
)

func newSessionID() string {
	n := atomic.AddInt64(&sessionCounter, 1)
	return fmt.Sprintf("__sess_%d_%d", n, time.Now().UnixNano()%10000)
}

func getSession(id string) (*HTTPSession, bool) {
	sessionStoreMu.Lock()
	defer sessionStoreMu.Unlock()
	s, ok := sessionStore[id]
	return s, ok
}

func createSession(followRedirects bool, proxy string, verifyTLS bool, timeoutMs int) *HTTPSession {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS}, //nolint:gosec
	}
	if proxy != "" {
		if proxyURL, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	checkRedirect := func(*http.Request, []*http.Request) error { return nil }
	if !followRedirects {
		checkRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	return &HTTPSession{
		client: &http.Client{
			Jar:           jar,
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: checkRedirect,
		},
		jar: jar,
		headers: map[string]string{
			"User-Agent": "Spectator/2.0 (+https://spectator-lang.dev)",
		},
	}
}

// ── Core request builder ───────────────────────────────────────────────────────

type RequestResult struct {
	Status   int
	Body     string
	Headers  map[string]interface{}
	Cookies  map[string]interface{}
	FinalURL string
	Length   int
	TimeMs   int64
}

func (r *RequestResult) toMap() map[string]interface{} {
	return map[string]interface{}{
		"status":  float64(r.Status),
		"body":    r.Body,
		"headers": r.Headers,
		"cookies": r.Cookies,
		"url":     r.FinalURL,
		"length":  float64(r.Length),
		"time":    float64(r.TimeMs),
	}
}

func doRequest(sess *HTTPSession, method, rawURL string, opts map[string]interface{}) (*RequestResult, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "http://" + rawURL
	}

	// Build body
	var bodyReader io.Reader
	bodyStr := ""
	if b, ok := opts["body"]; ok {
		bodyStr = toStr(b)
	}
	if bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(context.Background(), strings.ToUpper(method), rawURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %v", err)
	}

	// Apply session default headers
	if sess != nil {
		sess.mu.Lock()
		for k, v := range sess.headers {
			req.Header.Set(k, v)
		}
		sess.mu.Unlock()
	} else {
		req.Header.Set("User-Agent", "Spectator/2.0")
	}

	// Content-Type
	ct := "application/x-www-form-urlencoded"
	if v, ok := opts["type"]; ok {
		ct = toStr(v)
	}
	if bodyStr != "" {
		req.Header.Set("Content-Type", ct)
	}

	// Custom headers from opts
	if hdrs, ok := opts["headers"]; ok {
		if hmap, ok := hdrs.(map[string]interface{}); ok {
			for k, v := range hmap {
				req.Header.Set(k, toStr(v))
			}
		}
	}

	// Basic auth
	if auth, ok := opts["auth"]; ok {
		parts := strings.SplitN(toStr(auth), ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	// Bearer token
	if tok, ok := opts["token"]; ok {
		req.Header.Set("Authorization", "Bearer "+toStr(tok))
	}

	// Custom User-Agent
	if agent, ok := opts["agent"]; ok {
		req.Header.Set("User-Agent", toStr(agent))
	}

	// Manual cookies
	if cks, ok := opts["cookies"]; ok {
		if cmap, ok := cks.(map[string]interface{}); ok {
			for k, v := range cmap {
				req.AddCookie(&http.Cookie{Name: k, Value: toStr(v)})
			}
		}
	}

	// Build client
	var client *http.Client
	if sess != nil {
		client = sess.client
	} else {
		// one-shot client from opts
		follow := true
		if f, ok := opts["follow"]; ok {
			follow = isTruthy(f)
		}
		verify := true
		if v, ok := opts["verify"]; ok {
			verify = isTruthy(v)
		}
		timeoutMs := 10000
		if t, ok := opts["timeout"]; ok {
			timeoutMs = int(toFloat(t))
		}
		proxy := ""
		if p, ok := opts["proxy"]; ok {
			proxy = toStr(p)
		}
		tmp := createSession(follow, proxy, verify, timeoutMs)
		client = tmp.client
	}

	// Execute
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read body (with size cap)
	maxBody := 2 * 1024 * 1024 // 2 MB default
	if mb, ok := opts["maxbody"]; ok {
		maxBody = int(toFloat(mb))
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)))

	// Build headers map
	headers := make(map[string]interface{})
	for k, vs := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ", ")
	}

	// Build cookies map
	cookies := make(map[string]interface{})
	for _, ck := range resp.Cookies() {
		cookies[ck.Name] = ck.Value
	}

	return &RequestResult{
		Status:   resp.StatusCode,
		Body:     string(bodyBytes),
		Headers:  headers,
		Cookies:  cookies,
		FinalURL: resp.Request.URL.String(),
		Length:   len(bodyBytes),
		TimeMs:   elapsed,
	}, nil
}

// ── Interpreter bridge — called from callBuiltin ───────────────────────────────

func (interp *Interpreter) httpBuiltin(name string, args []interface{}) (interface{}, error) {
	switch name {

	// ── http(method, url, opts?) ────────────────────────────────────────────
	case "http":
		if len(args) < 2 {
			return nil, fmt.Errorf("http() requires method, url")
		}
		method := toStr(args[0])
		rawURL := toStr(args[1])
		opts := map[string]interface{}{}
		if len(args) >= 3 {
			if m, ok := args[2].(map[string]interface{}); ok {
				opts = m
			}
		}
		result, err := doRequest(nil, method, rawURL, opts)
		if err != nil {
			return nil, err
		}
		return result.toMap(), nil

	// ── httpSession() → session_id ─────────────────────────────────────────
	case "httpSession":
		follow := true
		verify := true
		timeoutMs := 10000
		proxy := ""
		if len(args) >= 1 {
			if m, ok := args[0].(map[string]interface{}); ok {
				if f, ok := m["follow"]; ok {
					follow = isTruthy(f)
				}
				if v, ok := m["verify"]; ok {
					verify = isTruthy(v)
				}
				if t, ok := m["timeout"]; ok {
					timeoutMs = int(toFloat(t))
				}
				if p, ok := m["proxy"]; ok {
					proxy = toStr(p)
				}
			}
		}
		sess := createSession(follow, proxy, verify, timeoutMs)
		id := newSessionID()
		sessionStoreMu.Lock()
		sessionStore[id] = sess
		sessionStoreMu.Unlock()
		return id, nil

	// ── httpSessionSet(s, key, val) — set default header or option ─────────
	case "httpSessionSet":
		if len(args) < 3 {
			return nil, fmt.Errorf("httpSessionSet() requires session, key, value")
		}
		id := toStr(args[0])
		key := toStr(args[1])
		val := toStr(args[2])
		sess, ok := getSession(id)
		if !ok {
			return nil, fmt.Errorf("httpSessionSet: unknown session %q", id)
		}
		sess.mu.Lock()
		sess.headers[key] = val
		sess.mu.Unlock()
		return nil, nil

	// ── httpDo(s, method, url, opts?) ──────────────────────────────────────
	case "httpDo":
		if len(args) < 3 {
			return nil, fmt.Errorf("httpDo() requires session, method, url")
		}
		id := toStr(args[0])
		method := toStr(args[1])
		rawURL := toStr(args[2])
		opts := map[string]interface{}{}
		if len(args) >= 4 {
			if m, ok := args[3].(map[string]interface{}); ok {
				opts = m
			}
		}
		sess, ok := getSession(id)
		if !ok {
			return nil, fmt.Errorf("httpDo: unknown session %q", id)
		}
		result, err := doRequest(sess, method, rawURL, opts)
		if err != nil {
			return nil, err
		}
		return result.toMap(), nil

	// ── httpSessionGet(s, url, opts?) ──────────────────────────────────────
	case "httpSessionGet":
		if len(args) < 2 {
			return nil, fmt.Errorf("httpSessionGet() requires session, url")
		}
		id := toStr(args[0])
		rawURL := toStr(args[1])
		opts := map[string]interface{}{}
		if len(args) >= 3 {
			if m, ok := args[2].(map[string]interface{}); ok {
				opts = m
			}
		}
		sess, ok := getSession(id)
		if !ok {
			return nil, fmt.Errorf("httpSessionGet: unknown session %q", id)
		}
		result, err := doRequest(sess, "GET", rawURL, opts)
		if err != nil {
			return nil, err
		}
		return result.toMap(), nil

	// ── httpSessionPost(s, url, body, opts?) ───────────────────────────────
	case "httpSessionPost":
		if len(args) < 3 {
			return nil, fmt.Errorf("httpSessionPost() requires session, url, body")
		}
		id := toStr(args[0])
		rawURL := toStr(args[1])
		body := toStr(args[2])
		opts := map[string]interface{}{}
		if len(args) >= 4 {
			if m, ok := args[3].(map[string]interface{}); ok {
				opts = m
			}
		}
		opts["body"] = body
		sess, ok := getSession(id)
		if !ok {
			return nil, fmt.Errorf("httpSessionPost: unknown session %q", id)
		}
		result, err := doRequest(sess, "POST", rawURL, opts)
		if err != nil {
			return nil, err
		}
		return result.toMap(), nil

	// ── httpSessionClose(s) ────────────────────────────────────────────────
	case "httpSessionClose":
		if len(args) < 1 {
			return nil, nil
		}
		id := toStr(args[0])
		sessionStoreMu.Lock()
		delete(sessionStore, id)
		sessionStoreMu.Unlock()
		return nil, nil

	// ── Response field accessors ───────────────────────────────────────────
	case "httpStatus":
		if len(args) < 1 {
			return float64(0), nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if s, ok := m["status"]; ok {
				return s, nil
			}
		}
		return float64(0), nil

	case "httpBody":
		if len(args) < 1 {
			return "", nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if b, ok := m["body"]; ok {
				return b, nil
			}
		}
		return "", nil

	case "httpHeaders":
		if len(args) < 1 {
			return map[string]interface{}{}, nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if h, ok := m["headers"]; ok {
				return h, nil
			}
		}
		return map[string]interface{}{}, nil

	case "httpHeader":
		// httpHeader(resp, "content-type")
		if len(args) < 2 {
			return "", nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if h, ok := m["headers"]; ok {
				if hmap, ok := h.(map[string]interface{}); ok {
					key := strings.ToLower(toStr(args[1]))
					if v, ok := hmap[key]; ok {
						return v, nil
					}
				}
			}
		}
		return "", nil

	case "httpCookies":
		if len(args) < 1 {
			return map[string]interface{}{}, nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if c, ok := m["cookies"]; ok {
				return c, nil
			}
		}
		return map[string]interface{}{}, nil

	case "httpCookie":
		// httpCookie(resp, "session_id")
		if len(args) < 2 {
			return "", nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if c, ok := m["cookies"]; ok {
				if cmap, ok := c.(map[string]interface{}); ok {
					if v, ok := cmap[toStr(args[1])]; ok {
						return v, nil
					}
				}
			}
		}
		return "", nil

	case "httpTime":
		if len(args) < 1 {
			return float64(0), nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if t, ok := m["time"]; ok {
				return t, nil
			}
		}
		return float64(0), nil

	// ── httpBrute(url, field, wordlist, opts?) ─────────────────────────────
	// Credential / param bruteforce. Sends POST for each word.
	// opts["success"] = "Welcome"  (string that means login success)
	// opts["fail"]    = "Invalid"  (string that means failure — stops on NOT seeing it)
	// opts["method"]  = "GET" | "POST" (default POST)
	// opts["extra"]   = "username=admin&" (extra fixed fields prepended)
	// opts["threads"] = 10
	case "httpBrute":
		if len(args) < 3 {
			return nil, fmt.Errorf("httpBrute() requires url, field, wordlist")
		}
		rawURL := toStr(args[0])
		field := toStr(args[1])
		wl, ok := args[2].([]interface{})
		if !ok {
			return nil, fmt.Errorf("httpBrute: wordlist must be a list")
		}
		opts := map[string]interface{}{}
		if len(args) >= 4 {
			if m, ok := args[3].(map[string]interface{}); ok {
				opts = m
			}
		}

		successStr := ""
		failStr := ""
		if s, ok := opts["success"]; ok {
			successStr = toStr(s)
		}
		if f, ok := opts["fail"]; ok {
			failStr = toStr(f)
		}
		method := "POST"
		if m, ok := opts["method"]; ok {
			method = strings.ToUpper(toStr(m))
		}
		extra := ""
		if e, ok := opts["extra"]; ok {
			extra = toStr(e)
		}

		threads := 1
		if t, ok := opts["threads"]; ok {
			threads = int(toFloat(t))
		}
		if threads < 1 {
			threads = 1
		}
		if threads > 50 {
			threads = 50
		}

		var results []interface{}
		var resultsMu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, threads)

		for _, word := range wl {
			wg.Add(1)
			sem <- struct{}{}
			go func(w string) {
				defer wg.Done()
				defer func() { <-sem }()

				body := extra + field + "=" + url.QueryEscape(w)
				reqOpts := map[string]interface{}{"body": body}
				// inherit timeout/headers from opts
				if h, ok := opts["headers"]; ok {
					reqOpts["headers"] = h
				}
				if t, ok := opts["timeout"]; ok {
					reqOpts["timeout"] = t
				}

				result, err := doRequest(nil, method, rawURL, reqOpts)
				if err != nil {
					return
				}

				hit := false
				if successStr != "" && strings.Contains(result.Body, successStr) {
					hit = true
				}
				if failStr != "" && !strings.Contains(result.Body, failStr) {
					hit = true
				}

				if hit {
					entry := map[string]interface{}{
						"word":   w,
						"status": float64(result.Status),
						"length": float64(result.Length),
					}
					resultsMu.Lock()
					results = append(results, entry)
					resultsMu.Unlock()
				}
			}(toStr(word))
		}
		wg.Wait()
		return results, nil

	// ── httpFuzz(url, marker, wordlist, opts?) ─────────────────────────────
	// Replace FUZZ marker in URL/body and fire each request.
	// Returns list of {word, status, length, body} for non-default responses.
	// opts["method"]  = "GET" (default)
	// opts["match"]   = [200, 301] — only return these status codes
	// opts["filter"]  = [404]      — exclude these status codes
	// opts["threads"] = 20
	// opts["show_body"] = true — include body in results (default false)
	case "httpFuzz":
		if len(args) < 3 {
			return nil, fmt.Errorf("httpFuzz() requires url, marker, wordlist")
		}
		template := toStr(args[0])
		marker := toStr(args[1])
		wl, ok := args[2].([]interface{})
		if !ok {
			return nil, fmt.Errorf("httpFuzz: wordlist must be a list")
		}
		opts := map[string]interface{}{}
		if len(args) >= 4 {
			if m, ok := args[3].(map[string]interface{}); ok {
				opts = m
			}
		}

		method := "GET"
		if m, ok := opts["method"]; ok {
			method = strings.ToUpper(toStr(m))
		}

		matchCodes := map[int]bool{}
		filterCodes := map[int]bool{404: true}
		if mc, ok := opts["match"]; ok {
			filterCodes = map[int]bool{} // if match given, clear default filter
			if list, ok := mc.([]interface{}); ok {
				for _, c := range list {
					matchCodes[int(toFloat(c))] = true
				}
			}
		}
		if fc, ok := opts["filter"]; ok {
			if list, ok := fc.([]interface{}); ok {
				for _, c := range list {
					filterCodes[int(toFloat(c))] = true
				}
			}
		}

		showBody := false
		if sb, ok := opts["show_body"]; ok {
			showBody = isTruthy(sb)
		}

		threads := 20
		if t, ok := opts["threads"]; ok {
			threads = int(toFloat(t))
		}
		if threads < 1 {
			threads = 1
		}
		if threads > 100 {
			threads = 100
		}

		var results []interface{}
		var resultsMu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, threads)

		for _, word := range wl {
			wg.Add(1)
			sem <- struct{}{}
			go func(w string) {
				defer wg.Done()
				defer func() { <-sem }()

				fuzzed := strings.ReplaceAll(template, marker, url.QueryEscape(w))
				reqOpts := map[string]interface{}{}
				if h, ok := opts["headers"]; ok {
					reqOpts["headers"] = h
				}
				if t, ok := opts["timeout"]; ok {
					reqOpts["timeout"] = t
				}
				if b, ok := opts["body"]; ok {
					reqOpts["body"] = strings.ReplaceAll(toStr(b), marker, url.QueryEscape(w))
				}

				result, err := doRequest(nil, method, fuzzed, reqOpts)
				if err != nil {
					return
				}

				// Apply match/filter
				if len(matchCodes) > 0 && !matchCodes[result.Status] {
					return
				}
				if filterCodes[result.Status] {
					return
				}

				entry := map[string]interface{}{
					"word":   w,
					"url":    fuzzed,
					"status": float64(result.Status),
					"length": float64(result.Length),
					"time":   float64(result.TimeMs),
				}
				if showBody {
					entry["body"] = result.Body
				}

				resultsMu.Lock()
				results = append(results, entry)
				resultsMu.Unlock()
			}(toStr(word))
		}
		wg.Wait()
		return results, nil

	// ── HTML parsing helpers ───────────────────────────────────────────────

	case "extractLinks":
		// extractLinks(html, base_url?)
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		html := toStr(args[0])
		base := ""
		if len(args) >= 2 {
			base = toStr(args[1])
		}
		re := regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
		matches := re.FindAllStringSubmatch(html, -1)
		seen := map[string]bool{}
		var links []interface{}
		for _, m := range matches {
			link := m[1]
			if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") {
				continue
			}
			if base != "" && !strings.HasPrefix(link, "http") {
				base = strings.TrimRight(base, "/")
				if !strings.HasPrefix(link, "/") {
					link = "/" + link
				}
				link = base + link
			}
			if !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
		return links, nil

	case "extractForms":
		// extractForms(html) → list of {action, method, fields: [name, ...]}
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		html := toStr(args[0])
		var forms []interface{}
		formRe := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
		attrRe := regexp.MustCompile(`(?i)(action|method)=["']?([^"'\s>]+)["']?`)
		inputRe := regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']+)["']`)
		for _, fm := range formRe.FindAllStringSubmatch(html, -1) {
			action, method := "", "GET"
			for _, attr := range attrRe.FindAllStringSubmatch(fm[1], -1) {
				switch strings.ToLower(attr[1]) {
				case "action":
					action = attr[2]
				case "method":
					method = strings.ToUpper(attr[2])
				}
			}
			var fields []interface{}
			for _, inp := range inputRe.FindAllStringSubmatch(fm[2], -1) {
				fields = append(fields, inp[1])
			}
			forms = append(forms, map[string]interface{}{
				"action": action,
				"method": method,
				"fields": fields,
			})
		}
		return forms, nil

	case "extractEmails":
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		re := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
		matches := re.FindAllString(toStr(args[0]), -1)
		seen := map[string]bool{}
		var out []interface{}
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
		return out, nil

	case "extractTitle":
		if len(args) < 1 {
			return "", nil
		}
		re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
		m := re.FindStringSubmatch(toStr(args[0]))
		if len(m) > 1 {
			return strings.TrimSpace(m[1]), nil
		}
		return "", nil

	case "extractMeta":
		// extractMeta(html, name) → content value
		if len(args) < 2 {
			return "", nil
		}
		html := toStr(args[0])
		name := strings.ToLower(toStr(args[1]))
		re := regexp.MustCompile(`(?i)<meta[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]+content=["']([^"']+)["']`)
		m := re.FindStringSubmatch(html)
		if len(m) > 1 {
			return m[1], nil
		}
		// try reversed attribute order
		re2 := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']` + regexp.QuoteMeta(name) + `["']`)
		m2 := re2.FindStringSubmatch(html)
		if len(m2) > 1 {
			return m2[1], nil
		}
		return "", nil

	case "stripHTML":
		if len(args) < 1 {
			return "", nil
		}
		re := regexp.MustCompile(`<[^>]+>`)
		return strings.TrimSpace(re.ReplaceAllString(toStr(args[0]), " ")), nil

	case "buildQuery":
		// buildQuery({"key": "val", ...}) → "key=val&key2=val2"
		if len(args) < 1 {
			return "", nil
		}
		m, ok := args[0].(map[string]interface{})
		if !ok {
			return toStr(args[0]), nil
		}
		vals := url.Values{}
		for k, v := range m {
			vals.Set(k, toStr(v))
		}
		return vals.Encode(), nil

	case "parseQuery":
		// parseQuery("key=val&key2=val2") → map
		if len(args) < 1 {
			return map[string]interface{}{}, nil
		}
		vals, err := url.ParseQuery(toStr(args[0]))
		if err != nil {
			return map[string]interface{}{}, nil
		}
		out := make(map[string]interface{})
		for k, vs := range vals {
			out[k] = vs[0]
		}
		return out, nil

	case "buildURL":
		// buildURL(base, {"path": "/api", "query": {"id": "1"}})
		if len(args) < 1 {
			return "", nil
		}
		base := toStr(args[0])
		if len(args) < 2 {
			return base, nil
		}
		opts2, ok := args[1].(map[string]interface{})
		if !ok {
			return base, nil
		}
		u, err := url.Parse(base)
		if err != nil {
			return base, nil
		}
		if path, ok := opts2["path"]; ok {
			u.Path = toStr(path)
		}
		if q, ok := opts2["query"]; ok {
			if qmap, ok := q.(map[string]interface{}); ok {
				vals := url.Values{}
				for k, v := range qmap {
					vals.Set(k, toStr(v))
				}
				u.RawQuery = vals.Encode()
			}
		}
		return u.String(), nil

	case "isRedirect":
		if len(args) < 1 {
			return false, nil
		}
		if m, ok := args[0].(map[string]interface{}); ok {
			if s, ok := m["status"]; ok {
				code := int(toFloat(s))
				return code >= 300 && code < 400, nil
			}
		}
		return false, nil

	case "httpMulti":
		// httpMulti(requests_list) — fire multiple requests concurrently
		// requests_list = [{"method":"GET","url":"...","opts":{...}}, ...]
		// returns list of response maps in same order
		if len(args) < 1 {
			return []interface{}{}, nil
		}
		reqs, ok := args[0].([]interface{})
		if !ok {
			return nil, fmt.Errorf("httpMulti: argument must be a list of request maps")
		}

		results := make([]interface{}, len(reqs))
		var wg sync.WaitGroup

		for i, r := range reqs {
			wg.Add(1)
			go func(idx int, req interface{}) {
				defer wg.Done()
				rmap, ok := req.(map[string]interface{})
				if !ok {
					results[idx] = nil
					return
				}
				method := "GET"
				rawURL := ""
				opts := map[string]interface{}{}
				if m, ok := rmap["method"]; ok {
					method = toStr(m)
				}
				if u, ok := rmap["url"]; ok {
					rawURL = toStr(u)
				}
				if o, ok := rmap["opts"]; ok {
					if om, ok := o.(map[string]interface{}); ok {
						opts = om
					}
				}
				if b, ok := rmap["body"]; ok {
					opts["body"] = toStr(b)
				}
				result, err := doRequest(nil, method, rawURL, opts)
				if err != nil {
					results[idx] = nil
					return
				}
				results[idx] = result.toMap()
			}(i, r)
		}
		wg.Wait()
		return results, nil

	case "httpDownload":
		// httpDownload(url, filepath, opts?) — download a file to disk
		if len(args) < 2 {
			return nil, fmt.Errorf("httpDownload() requires url, filepath")
		}
		rawURL := toStr(args[0])
		filePath := toStr(args[1])
		opts := map[string]interface{}{"maxbody": 100 * 1024 * 1024} // 100 MB cap
		if len(args) >= 3 {
			if m, ok := args[2].(map[string]interface{}); ok {
				for k, v := range m {
					opts[k] = v
				}
			}
		}
		result, err := doRequest(nil, "GET", rawURL, opts)
		if err != nil {
			return nil, err
		}
		if err := writeFileBytes(filePath, []byte(result.Body)); err != nil {
			return nil, err
		}
		return float64(result.Length), nil
	}

	return nil, fmt.Errorf("unknown http builtin %q", name)
}

func writeFileBytes(path string, data []byte) error {
	return bytesWriteFile(path, data)
}

func bytesWriteFile(path string, data []byte) error {
	f, err := openFileForWrite(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	f.Close()
	return err
}

func openFileForWrite(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
}

// buildHTTPOpts converts a Spectator map value to an opts map safely
func buildHTTPOpts(v interface{}) map[string]interface{} {
	if v == nil {
		return map[string]interface{}{}
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

// wrapHTTPBody builds the body string from multiple convenience forms:
//
//	string → used directly
//	map    → URL-encoded key=val&key2=val2
func wrapHTTPBody(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if m, ok := v.(map[string]interface{}); ok {
		vals := url.Values{}
		for k, val := range m {
			vals.Set(k, toStr(val))
		}
		return vals.Encode()
	}
	return toStr(v)
}

// httpOptBytes stores the bytes buffer used in request body assembly
var httpOptBytes = &bytes.Buffer{}
