package ohttp_gateway_traefik_plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/bhttp"
	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/ohttp"
)

const (
	problemTypeKey     = "https://iana.org/assignments/http-problem-types#ohttp-key"
	problemContentType = "application/problem+json"
)

// Gateway is the Oblivious HTTP gateway middleware.
type Gateway struct {
	next             http.Handler
	name             string
	logger           *slog.Logger
	gateway          *ohttp.Gateway
	keyConfigs       []byte
	gatewayPath      string
	keysPath         string
	keysCacheControl string
	allowedTargets   []string
	forwardURL       *url.URL
	transport        http.RoundTripper
	forwardTimeout   time.Duration
	maxRequestSize   int64
	maxResponseSize  int64
	paddingBlockSize int
}

// New creates the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, errors.New("ohttp gateway: missing configuration")
	}
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("ohttp gateway %s: %w", name, err)
	}
	keys, advertised, err := loadKeys(config.Keys)
	if err != nil {
		return nil, fmt.Errorf("ohttp gateway %s: %w", name, err)
	}
	gw, err := ohttp.NewGateway(keys)
	if err != nil {
		return nil, fmt.Errorf("ohttp gateway %s: %w", name, err)
	}
	keyConfigs, err := ohttp.MarshalKeyConfigs(advertised)
	if err != nil {
		return nil, fmt.Errorf("ohttp gateway %s: %w", name, err)
	}

	g := &Gateway{
		next:             next,
		name:             name,
		logger:           newLogger(config.LogLevel, name),
		gateway:          gw,
		keyConfigs:       keyConfigs,
		gatewayPath:      config.GatewayPath,
		keysPath:         config.KeysPath,
		keysCacheControl: "max-age=" + strconv.Itoa(config.KeysCacheMaxAge),
		maxRequestSize:   config.MaxRequestSize,
		maxResponseSize:  config.MaxResponseSize,
		paddingBlockSize: config.PaddingBlockSize,
	}
	for _, target := range config.AllowedTargets {
		g.allowedTargets = append(g.allowedTargets, strings.ToLower(target))
	}

	if config.ForwardURL != "" {
		u, err := url.Parse(config.ForwardURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("ohttp gateway %s: invalid forwardUrl %q", name, config.ForwardURL)
		}
		timeout, err := parseForwardTimeout(config.ForwardTimeout)
		if err != nil {
			return nil, fmt.Errorf("ohttp gateway %s: %w", name, err)
		}
		g.forwardURL = u
		g.forwardTimeout = timeout
		// The transport is used directly rather than through an http.Client:
		// redirects must be returned to the client, not followed, and an
		// interpreted CheckRedirect callback is not handled well by Yaegi.
		g.transport = newTransport()
	}

	for _, key := range keys {
		g.logger.Info("loaded key",
			"keyId", key.Config.KeyID, "kem", key.Config.KEM.String(), "retired", !containsKey(advertised, key.Config.KeyID))
	}
	return g, nil
}

func containsKey(configs []ohttp.KeyConfig, id uint8) bool {
	for _, c := range configs {
		if c.KeyID == id {
			return true
		}
	}
	return false
}

func newLogger(level, name string) *slog.Logger {
	var l slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		l = slog.LevelDebug
	case "WARN":
		l = slog.LevelWarn
	case "ERROR":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l})
	return slog.New(handler).With("plugin", "ohttp-gateway", "middleware", name)
}

func (g *Gateway) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case g.gatewayPath:
		switch req.Method {
		case http.MethodPost:
			g.serveGateway(rw, req)
		case http.MethodGet, http.MethodHead:
			g.serveKeys(rw, req)
		default:
			rw.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	case g.keysPath:
		if g.keysPath == "" {
			g.next.ServeHTTP(rw, req)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			rw.Header().Set("Allow", "GET, HEAD")
			http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		g.serveKeys(rw, req)
	default:
		g.next.ServeHTTP(rw, req)
	}
}

// serveKeys returns the advertised key configurations (RFC 9458, Section 3.2
// and RFC 9540).
func (g *Gateway) serveKeys(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", ohttp.KeysMediaType)
	rw.Header().Set("Cache-Control", g.keysCacheControl)
	rw.Header().Set("Content-Length", strconv.Itoa(len(g.keyConfigs)))
	rw.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		_, _ = rw.Write(g.keyConfigs)
	}
}

// serveGateway decapsulates an Encapsulated Request, dispatches it to the
// target and encapsulates the response (RFC 9458, Section 5).
func (g *Gateway) serveGateway(rw http.ResponseWriter, req *http.Request) {
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != ohttp.RequestMediaType {
		http.Error(rw, "content type must be "+ohttp.RequestMediaType, http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, g.maxRequestSize+1))
	if err != nil {
		g.logger.Debug("failed to read request body", "error", err)
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if int64(len(body)) > g.maxRequestSize {
		http.Error(rw, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}

	binaryRequest, respCtx, err := g.gateway.DecapsulateRequest(body)
	if err != nil {
		g.logger.Debug("failed to decapsulate request", "error", err)
		// Errors before decapsulation cannot be encrypted (RFC 9458, Section 5.2).
		if errors.Is(err, ohttp.ErrMalformedRequest) {
			http.Error(rw, "malformed encapsulated request", http.StatusBadRequest)
			return
		}
		writeKeyProblem(rw, err)
		return
	}

	// From here on, every answer must be an Encapsulated Response.
	response := g.handleInnerRequest(req, binaryRequest)
	g.writeEncapsulatedResponse(rw, respCtx, response)
}

func writeKeyProblem(rw http.ResponseWriter, err error) {
	title := "key configuration mismatch"
	switch {
	case errors.Is(err, ohttp.ErrUnknownKey):
		title = "key identifier unknown"
	case errors.Is(err, ohttp.ErrUnsupportedSuite):
		title = "unsupported key configuration"
	}
	rw.Header().Set("Content-Type", problemContentType)
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(rw, `{"type":%q,"title":%q}`, problemTypeKey, title)
}

func (g *Gateway) writeEncapsulatedResponse(rw http.ResponseWriter, respCtx *ohttp.ResponseContext, response *bhttp.Response) {
	binaryResponse, err := response.Marshal()
	if err != nil {
		g.logger.Error("failed to encode response", "error", err)
		binaryResponse, _ = errorResponse(http.StatusBadGateway).Marshal()
	}
	if g.paddingBlockSize > 0 {
		if rem := len(binaryResponse) % g.paddingBlockSize; rem != 0 {
			binaryResponse = append(binaryResponse, make([]byte, g.paddingBlockSize-rem)...)
		}
	}
	encResponse, err := respCtx.EncapsulateResponse(rand.Reader, binaryResponse)
	if err != nil {
		g.logger.Error("failed to encapsulate response", "error", err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", ohttp.ResponseMediaType)
	rw.Header().Set("Cache-Control", "private, no-store")
	rw.Header().Set("Content-Length", strconv.Itoa(len(encResponse)))
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(encResponse)
}

func errorResponse(status int) *bhttp.Response {
	return &bhttp.Response{
		StatusCode: status,
		Header:     []bhttp.Field{{Name: "content-type", Value: "text/plain; charset=utf-8"}},
		Body:       []byte(http.StatusText(status) + "\n"),
	}
}

// handleInnerRequest decodes the binary request, sends it to the target and
// returns the binary response. Failures are turned into error responses.
func (g *Gateway) handleInnerRequest(outer *http.Request, binaryRequest []byte) *bhttp.Response {
	msg, err := bhttp.UnmarshalRequest(binaryRequest)
	if err != nil {
		g.logger.Debug("invalid binary request", "error", err)
		return errorResponse(http.StatusBadRequest)
	}
	inner, status, err := g.buildInnerRequest(outer, msg)
	if err != nil {
		g.logger.Debug("rejected inner request", "error", err, "status", status)
		return errorResponse(status)
	}
	g.logger.Debug("dispatching inner request", "method", inner.Method, "host", inner.Host, "path", inner.URL.Path)
	if g.forwardURL != nil {
		return g.forward(inner)
	}
	return g.serveNext(inner)
}

func (g *Gateway) buildInnerRequest(outer *http.Request, msg *bhttp.Request) (*http.Request, int, error) {
	if msg.Method == http.MethodConnect {
		return nil, http.StatusNotImplemented, errors.New("CONNECT is not supported")
	}
	switch msg.Scheme {
	case "https", "http":
	default:
		return nil, http.StatusBadRequest, fmt.Errorf("unsupported scheme %q", msg.Scheme)
	}
	for _, fields := range [][]bhttp.Field{msg.Header, msg.Trailer} {
		for _, f := range fields {
			if !validFieldName(f.Name) || !validFieldValue(f.Value) {
				return nil, http.StatusBadRequest, fmt.Errorf("invalid field %q", f.Name)
			}
		}
	}
	header := bhttp.HeaderFromFields(msg.Header)
	stripForwardingHeaders(header)
	if expect := header.Get("Expect"); expect != "" {
		// RFC 9458, Section 5.1: 100-continue cannot be honored.
		return nil, http.StatusExpectationFailed, fmt.Errorf("unsupported expectation %q", expect)
	}

	authority := msg.Authority
	if authority == "" {
		authority = header.Get("Host")
	}
	header.Del("Host")
	if authority == "" {
		authority = outer.Host
	}
	if !validAuthority(authority) {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid authority %q", authority)
	}
	if !g.targetAllowed(authority) {
		return nil, http.StatusForbidden, fmt.Errorf("target %q is not allowed", authority)
	}

	path := msg.Path
	if path == "*" && msg.Method != http.MethodOptions || path != "*" && !strings.HasPrefix(path, "/") {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid path %q", path)
	}

	// ParseRequestURI keeps "//host/path" as a path instead of an authority.
	target, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	inner, err := http.NewRequestWithContext(outer.Context(), msg.Method, "/", bytes.NewReader(msg.Body))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	inner.URL = target
	inner.Host = authority
	inner.Header = header
	inner.RequestURI = path
	inner.RemoteAddr = outer.RemoteAddr
	inner.TLS = outer.TLS
	if len(msg.Body) == 0 {
		inner.Body = http.NoBody
		inner.GetBody = nil
	}
	return inner, 0, nil
}

// stripForwardingHeaders removes proxy-added fields supplied by the client.
// Inner requests do not go through Traefik's entry point, which normally
// drops untrusted X-Forwarded-* headers, so a client could otherwise spoof
// them towards the target.
func stripForwardingHeaders(header http.Header) {
	for name := range header {
		if strings.HasPrefix(name, "X-Forwarded-") || name == "Forwarded" || name == "X-Real-Ip" {
			delete(header, name)
		}
	}
}

// targetAllowed matches an authority against allowedTargets. Entries without a
// port match any port; a leading "*." matches any subdomain.
func (g *Gateway) targetAllowed(authority string) bool {
	if len(g.allowedTargets) == 0 {
		return true
	}
	authority = strings.ToLower(authority)
	host := strings.Trim(authority, "[]")
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	for _, allowed := range g.allowedTargets {
		candidate, pattern := host, strings.Trim(allowed, "[]")
		if _, _, err := net.SplitHostPort(allowed); err == nil {
			candidate, pattern = authority, allowed
		}
		if strings.HasPrefix(pattern, "*.") {
			if strings.HasSuffix(candidate, pattern[1:]) {
				return true
			}
			continue
		}
		if candidate == pattern {
			return true
		}
	}
	return false
}

// serveNext dispatches the inner request to the next handler of the chain and
// captures its response.
func (g *Gateway) serveNext(inner *http.Request) (resp *bhttp.Response) {
	rec := newResponseRecorder(g.maxResponseSize)
	defer func() {
		// The reverse proxy aborts with http.ErrAbortHandler when it cannot copy
		// the upstream response: report it as a gateway error.
		if r := recover(); r != nil {
			if !isAbortHandler(r) {
				panic(r)
			}
			g.logger.Debug("target aborted the response")
			resp = errorResponse(http.StatusBadGateway)
		}
	}()
	g.next.ServeHTTP(rec, inner)
	if rec.overflow {
		g.logger.Warn("target response exceeds maxResponseSize", "limit", g.maxResponseSize)
		return errorResponse(http.StatusBadGateway)
	}
	return &bhttp.Response{
		StatusCode: rec.statusCode(),
		Header:     bhttp.FieldsFromHeader(rec.header),
		Body:       rec.body.Bytes(),
	}
}

// isAbortHandler reports whether a recovered value is http.ErrAbortHandler.
// Yaegi hands recovered values over as reflect.Value, hence the unwrapping.
func isAbortHandler(recovered any) bool {
	if rv, ok := recovered.(reflect.Value); ok && rv.IsValid() && rv.CanInterface() {
		recovered = rv.Interface()
	}
	err, ok := recovered.(error)
	return ok && errors.Is(err, http.ErrAbortHandler)
}

// forward sends the inner request to forwardURL.
func (g *Gateway) forward(inner *http.Request) *bhttp.Response {
	target := *g.forwardURL
	target.Path = strings.TrimSuffix(target.Path, "/") + inner.URL.Path
	target.RawPath = ""
	target.RawQuery = inner.URL.RawQuery

	ctx, cancel := context.WithTimeout(inner.Context(), g.forwardTimeout)
	defer cancel()
	outReq, err := http.NewRequestWithContext(ctx, inner.Method, target.String(), inner.Body)
	if err != nil {
		return errorResponse(http.StatusBadRequest)
	}
	outReq.ContentLength = inner.ContentLength
	outReq.Header = inner.Header
	outReq.Host = inner.Host

	resp, err := g.transport.RoundTrip(outReq)
	if err != nil {
		g.logger.Debug("forward request failed", "error", err)
		return errorResponse(forwardErrorStatus(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, g.maxResponseSize+1))
	if err != nil {
		g.logger.Debug("failed to read forwarded response", "error", err)
		return errorResponse(forwardErrorStatus(err))
	}
	if int64(len(body)) > g.maxResponseSize {
		g.logger.Warn("target response exceeds maxResponseSize", "limit", g.maxResponseSize)
		return errorResponse(http.StatusBadGateway)
	}
	return &bhttp.Response{
		StatusCode: resp.StatusCode,
		Header:     bhttp.FieldsFromHeader(resp.Header),
		Body:       body,
		Trailer:    bhttp.FieldsFromHeader(resp.Trailer),
	}
}

func forwardErrorStatus(err error) int {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func newTransport() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}
	return http.DefaultTransport
}

func validAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "/?#@ \t\r\n") {
		return false
	}
	u, err := url.Parse("http://" + authority)
	return err == nil && u.Host == authority
}

func validFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
	}
}

func validFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// responseRecorder captures the target response, bounding its size.
type responseRecorder struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	limit       int64
	wroteHeader bool
	overflow    bool
}

func newResponseRecorder(limit int64) *responseRecorder {
	return &responseRecorder{header: make(http.Header), limit: limit}
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) WriteHeader(status int) {
	// Informational responses cannot be streamed through the encapsulation
	// (RFC 9458, Section 5.1) and are dropped.
	if r.wroteHeader || status < 200 {
		return
	}
	r.status = status
	r.wroteHeader = true
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if r.overflow {
		return len(b), nil
	}
	if int64(r.body.Len()+len(b)) > r.limit {
		// Keep consuming so the target completes; the response is discarded.
		r.overflow = true
		r.body.Reset()
		return len(b), nil
	}
	return r.body.Write(b)
}

// Flush is a no-op: the response is only sent once complete.
func (r *responseRecorder) Flush() {}

func (r *responseRecorder) statusCode() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
