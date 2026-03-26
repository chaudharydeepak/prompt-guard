package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
)

// targetSuffixes are hostname suffixes we intercept.
var targetSuffixes = []string{
	"api.openai.com",
	"api.anthropic.com",
	"api.githubcopilot.com",
	"copilot-proxy.githubusercontent.com",
	".githubcopilot.com",
	".openai.com",
	".anthropic.com",
}

func isTarget(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	for _, suffix := range targetSuffixes {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

type proxy struct {
	ca  *CA
	db  *store.Store
	eng *inspector.Engine
}

// Start runs the HTTP proxy on the given port. Blocks until error.
func Start(port int, ca *CA, db *store.Store, eng *inspector.Engine) error {
	p := &proxy{ca: ca, db: db, eng: eng}
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: p,
	}
	log.Printf("proxy: listening on :%d", port)
	return srv.ListenAndServe()
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handleCONNECT handles HTTPS CONNECT tunnels.
func (p *proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	// Acknowledge the CONNECT
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")

	if isTarget(r.Host) {
		p.mitm(clientConn, r.Host)
	} else {
		tunnel(clientConn, r.Host)
	}
}

// mitm performs TLS man-in-the-middle interception.
func (p *proxy) mitm(clientConn net.Conn, hostport string) {
	defer clientConn.Close()

	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	cert, err := p.ca.IssueCert(hostname)
	if err != nil {
		log.Printf("mitm: cert error %s: %v", hostname, err)
		return
	}

	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		// Likely: client doesn't trust our CA yet
		log.Printf("mitm: TLS handshake failed for %s — is the CA cert trusted? (%v)", hostname, err)
		return
	}
	defer tlsClient.Close()

	br := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = hostport

		// Buffer the request body so we can inspect it then re-send it.
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		log.Printf("REQUEST: %s %s%s body=%d bytes stream=%v", req.Method, stripPort(hostport), req.URL.Path, len(body), IsStreaming(body))
		prompts := ExtractPrompts(body)
		log.Printf("EXTRACTED: %d prompt(s)", len(prompts))
		for i, p := range prompts {
			log.Printf("  [%d] %.120s", i, p)
		}
		if len(prompts) == 0 && len(body) > 0 && len(body) < 4096 && (body[0] == '{' || body[0] == '[') {
			end := 2000
			if len(body) < end {
				end = len(body)
			}
			log.Printf("BODY SAMPLE: %s", string(body[:end]))
		}

		// Inspect before forwarding; block if a blocking rule fired.
		if blocked, msg := p.inspectAndStore(req, hostport, body); blocked {
			writeBlockedResponse(tlsClient, msg, IsStreaming(body), req.URL.Path)
			return
		}

		// Forward to real upstream and pipe response back
		if err := p.forward(tlsClient, req, hostport); err != nil {
			return
		}
	}
}

// forward dials the real upstream, sends the request, and writes the response back to dst.
func (p *proxy) forward(dst net.Conn, req *http.Request, hostport string) error {
	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	up, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 15 * time.Second},
		"tcp", hostport,
		&tls.Config{
			ServerName: hostname,
			NextProtos: []string{"http/1.1"},
		},
	)
	if err != nil {
		return err
	}
	defer up.Close()

	if err := req.Write(up); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return resp.Write(dst)
}

// inspectAndStore stores every intercepted prompt.
// Returns (blocked, assistantMessage) — if blocked is true the caller should
// write assistantMessage back to the client instead of forwarding.
func (p *proxy) inspectAndStore(req *http.Request, host string, body []byte) (bool, string) {
	prompts := ExtractPrompts(body)
	if len(prompts) == 0 {
		return false, ""
	}

	combined := strings.Join(prompts, "\n\n")
	result := p.eng.Inspect(combined)

	status := store.StatusClean
	if result.Blocked {
		status = store.StatusBlocked
	} else if len(result.Matches) > 0 {
		status = store.StatusFlagged
	}

	err := p.db.SavePrompt(store.Prompt{
		Timestamp: time.Now(),
		Host:      stripPort(host),
		Path:      req.URL.Path,
		Prompt:    combined,
		Status:    status,
		Matches:   result.Matches,
	})
	if err != nil {
		log.Printf("store: %v", err)
	} else if status != store.StatusClean {
		log.Printf("%s: %s%s — %d rule(s)", strings.ToUpper(string(status)), stripPort(host), req.URL.Path, len(result.Matches))
	}

	if !result.Blocked {
		return false, ""
	}

	// Build a human-readable list of triggered blocking rules.
	var ruleNames []string
	for _, m := range result.Matches {
		if m.Mode == "block" {
			ruleNames = append(ruleNames, m.RuleName)
		}
	}
	msg := "⚠️ **Prompt Guard blocked this request.**\n\n" +
		"Your prompt contained sensitive information detected by the following rule(s):\n"
	for _, name := range ruleNames {
		msg += "- " + name + "\n"
	}
	msg += "\nThis request was **not forwarded** to the AI. Please remove the sensitive data and try again."
	return true, msg
}

// writeBlockedResponse returns a well-formed response so the client renders
// the blocked message in the chat UI.
// Anthropic (/v1/messages) and OpenAI (/chat/completions) have different
// streaming formats; non-streaming also differs.
func writeBlockedResponse(conn net.Conn, assistantMsg string, streaming bool, path string) {
	if strings.Contains(path, "/v1/messages") {
		// Anthropic event-stream format.
		if streaming {
			msgStart := `{"type":"message_start","message":{"id":"msg_blocked","type":"message","role":"assistant","content":[],"model":"claude-haiku-4.5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}}`
			cbStart := `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`
			cbDelta := fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":%s}}`, jsonString(assistantMsg))
			cbStop := `{"type":"content_block_stop","index":0}`
			msgDelta := `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`
			msgStop := `{"type":"message_stop"}`
			body := "event: message_start\ndata: " + msgStart + "\n\n" +
				"event: content_block_start\ndata: " + cbStart + "\n\n" +
				"event: content_block_delta\ndata: " + cbDelta + "\n\n" +
				"event: content_block_stop\ndata: " + cbStop + "\n\n" +
				"event: message_delta\ndata: " + msgDelta + "\n\n" +
				"event: message_stop\ndata: " + msgStop + "\n\n"
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n%s",
				body,
			)
		} else {
			body := fmt.Sprintf(
				`{"id":"msg_blocked","type":"message","role":"assistant","content":[{"type":"text","text":%s}],"model":"claude-haiku-4.5","stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":1}}`,
				jsonString(assistantMsg),
			)
			fmt.Fprintf(conn,
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				len(body), body,
			)
		}
		return
	}

	// OpenAI format (chat/completions and everything else).
	if streaming {
		chunk := fmt.Sprintf(
			`{"id":"chatcmpl-blocked","object":"chat.completion.chunk","created":0,"model":"prompt-guard",`+
				`"choices":[{"index":0,"delta":{"role":"assistant","content":%s},"finish_reason":null}]}`,
			jsonString(assistantMsg),
		)
		done := `{"id":"chatcmpl-blocked","object":"chat.completion.chunk","created":0,"model":"prompt-guard",` +
			`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
		body := "data: " + chunk + "\n\ndata: " + done + "\n\ndata: [DONE]\n\n"
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n%s",
			body,
		)
	} else {
		body := fmt.Sprintf(
			`{"id":"chatcmpl-blocked","object":"chat.completion","created":0,"model":"prompt-guard",`+
				`"choices":[{"index":0,"message":{"role":"assistant","content":%s},"finish_reason":"stop"}],`+
				`"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`,
			jsonString(assistantMsg),
		)
		fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body), body,
		)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// handlePlainHTTP proxies plain HTTP requests (non-CONNECT).
func (p *proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// tunnel blindly copies bytes between client and upstream (non-intercepted CONNECT).
func tunnel(client net.Conn, hostport string) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", hostport, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
	<-done
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
