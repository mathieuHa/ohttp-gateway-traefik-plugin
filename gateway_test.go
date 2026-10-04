package ohttp_gateway_traefik_plugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/bhttp"
	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/ohttp"
)

const (
	testSeed  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testSeed2 = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	// Private key of the RFC 9458 example.
	rfcPrivateKey = "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a"
)

func testConfig() *Config {
	cfg := CreateConfig()
	cfg.LogLevel = "ERROR"
	cfg.Keys = []KeyConfig{{KeyID: 1, Seed: testSeed}}
	return cfg
}

func newTestGateway(t *testing.T, cfg *Config, next http.Handler) http.Handler {
	t.Helper()
	if next == nil {
		next = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusTeapot)
		})
	}
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func fetchKeyConfigs(t *testing.T, h http.Handler, path string) []ohttp.KeyConfig {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://gateway.example"+path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ohttp.KeysMediaType {
		t.Fatalf("content type = %q", ct)
	}
	configs, err := ohttp.ParseKeyConfigs(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return configs
}

// roundTrip encapsulates msg, sends it to the gateway and decapsulates the
// response.
func roundTrip(t *testing.T, h http.Handler, client *ohttp.Client, msg *bhttp.Request) (*bhttp.Response, []byte) {
	t.Helper()
	binaryRequest, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encReq, clientCtx, err := client.EncapsulateRequest(rand.Reader, binaryRequest)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://gateway.example"+DefaultGatewayPath, bytes.NewReader(encReq))
	req.Header.Set("Content-Type", ohttp.RequestMediaType)
	req.Header.Set("X-Relay-Secret", "must-not-leak")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("outer status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != ohttp.ResponseMediaType {
		t.Fatalf("outer content type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
		t.Fatalf("outer cache control = %q", cc)
	}
	binaryResponse, err := clientCtx.DecapsulateResponse(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bhttp.UnmarshalResponse(binaryResponse)
	if err != nil {
		t.Fatal(err)
	}
	return resp, binaryResponse
}

func newClient(t *testing.T, h http.Handler) *ohttp.Client {
	t.Helper()
	configs := fetchKeyConfigs(t, h, DefaultGatewayPath)
	client, err := ohttp.NewClient(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestKeyConfigEndpoints(t *testing.T) {
	cfg := testConfig()
	cfg.KeysPath = "/ohttp-keys"
	cfg.Keys = []KeyConfig{
		{KeyID: 1, Seed: testSeed, Suites: []string{"HKDF-SHA256/AES-128-GCM"}},
		{KeyID: 2, KEM: "P-256", Seed: testSeed2, Suites: []string{"hkdf_sha384/aes_256_gcm", "HKDF-SHA512/AES-128-GCM"}},
		{KeyID: 3, PrivateKey: rfcPrivateKey, Retired: true},
	}
	h := newTestGateway(t, cfg, nil)

	for _, path := range []string{DefaultGatewayPath, "/ohttp-keys"} {
		configs := fetchKeyConfigs(t, h, path)
		if len(configs) != 2 {
			t.Fatalf("%s: got %d configs, retired key must not be advertised", path, len(configs))
		}
		if configs[0].KeyID != 1 || configs[0].KEM != hpke.KEMX25519HKDFSHA256 || len(configs[0].Suites) != 1 {
			t.Fatalf("config 0 = %+v", configs[0])
		}
		if configs[1].KeyID != 2 || configs[1].KEM != hpke.KEMP256HKDFSHA256 || len(configs[1].Suites) != 2 ||
			configs[1].Suites[0] != (ohttp.SymmetricSuite{KDF: hpke.KDFHKDFSHA384, AEAD: hpke.AEADAES256GCM}) {
			t.Fatalf("config 1 = %+v", configs[1])
		}
	}

	// The seed derivation is deterministic.
	sk, err := hpke.KEMX25519HKDFSHA256.DeriveKeyPair(mustHex(t, testSeed))
	if err != nil {
		t.Fatal(err)
	}
	if !fetchKeyConfigs(t, h, DefaultGatewayPath)[0].PublicKey.Equal(sk.PublicKey()) {
		t.Fatal("seeded public key mismatch")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "https://gateway.example/ohttp-keys", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "0" {
		t.Fatalf("HEAD: status %d, body %d, length %q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Length"))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=3600" {
		t.Fatalf("cache control = %q", cc)
	}

	for path, allow := range map[string]string{DefaultGatewayPath: "GET, HEAD, POST", "/ohttp-keys": "GET, HEAD"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "https://gateway.example"+path, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != allow {
			t.Fatalf("DELETE %s: status %d, allow %q", path, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestPassThrough(t *testing.T) {
	called := false
	h := newTestGateway(t, testConfig(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		called = true
		if req.Header.Get("X-Original") != "1" {
			t.Errorf("pass-through request was modified")
		}
		rw.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodPost, "https://gateway.example/other", strings.NewReader("x"))
	req.Header.Set("X-Original", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusTeapot {
		t.Fatalf("pass-through: called=%v status=%d", called, rec.Code)
	}
}

func TestGatewayRoundTrip(t *testing.T) {
	h := newTestGateway(t, testConfig(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		switch {
		case req.Method != http.MethodPost:
			t.Errorf("method = %s", req.Method)
		case req.Host != "api.example.com":
			t.Errorf("host = %s", req.Host)
		case req.URL.Path != "/v1/items" || req.URL.RawQuery != "q=1&r=2":
			t.Errorf("url = %s", req.URL)
		case req.RequestURI != "/v1/items?q=1&r=2":
			t.Errorf("request URI = %s", req.RequestURI)
		case req.Header.Get("Content-Type") != "application/json" || len(req.Header.Values("X-Multi")) != 2:
			t.Errorf("header = %v", req.Header)
		case req.Header.Get("X-Relay-Secret") != "" || req.Header.Get("Host") != "":
			t.Errorf("outer or host headers leaked: %v", req.Header)
		case req.Header.Get("X-Forwarded-For") != "" || req.Header.Get("X-Real-Ip") != "" || req.Header.Get("Forwarded") != "":
			t.Errorf("client-supplied forwarding headers must be stripped: %v", req.Header)
		case string(body) != `{"name":"value"}` || req.ContentLength != int64(len(body)):
			t.Errorf("body = %q (length %d)", body, req.ContentLength)
		}
		rw.Header().Set("Content-Type", "text/plain")
		rw.Header().Set("Connection", "close")
		rw.Header().Add("Set-Cookie", "a=1")
		rw.Header().Add("Set-Cookie", "b=2")
		rw.WriteHeader(http.StatusCreated)
		_, _ = rw.Write([]byte("created "))
		_, _ = rw.Write([]byte("item"))
	}))

	resp, _ := roundTrip(t, h, newClient(t, h), &bhttp.Request{
		Method: http.MethodPost, Scheme: "https", Authority: "api.example.com", Path: "/v1/items?q=1&r=2",
		Header: []bhttp.Field{
			{Name: "content-type", Value: "application/json"},
			{Name: "x-multi", Value: "1"},
			{Name: "x-multi", Value: "2"},
			{Name: "connection", Value: "keep-alive"},
			{Name: "x-forwarded-for", Value: "6.6.6.6"},
			{Name: "x-real-ip", Value: "6.6.6.6"},
			{Name: "forwarded", Value: "for=6.6.6.6"},
		},
		Body: []byte(`{"name":"value"}`),
	})
	if resp.StatusCode != http.StatusCreated || string(resp.Body) != "created item" {
		t.Fatalf("response = %d %q", resp.StatusCode, resp.Body)
	}
	header := bhttp.HeaderFromFields(resp.Header)
	if header.Get("Content-Type") != "text/plain" || len(header.Values("Set-Cookie")) != 2 {
		t.Fatalf("response header = %v", header)
	}
	for _, f := range resp.Header {
		if f.Name == "connection" {
			t.Fatal("connection-specific field leaked into the response")
		}
	}
}

func TestPathIsNotAnAuthority(t *testing.T) {
	var got *http.Request
	h := newTestGateway(t, testConfig(), http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = req
	}))
	roundTrip(t, h, newClient(t, h), &bhttp.Request{Method: "GET", Scheme: "https", Authority: "a.example", Path: "//evil.example/x?y=1"})
	if got == nil || got.Host != "a.example" || got.URL.Host != "" || got.URL.Path != "//evil.example/x" || got.URL.RawQuery != "y=1" {
		t.Fatalf("request = %+v", got)
	}
}

func TestGatewayAuthorityFallbacks(t *testing.T) {
	var hosts []string
	h := newTestGateway(t, testConfig(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		hosts = append(hosts, req.Host)
		if req.Body != http.NoBody {
			t.Errorf("empty body should be http.NoBody")
		}
	}))
	client := newClient(t, h)
	// Host header when the authority is empty, then the gateway host.
	roundTrip(t, h, client, &bhttp.Request{Method: "GET", Scheme: "https", Path: "/", Header: []bhttp.Field{{Name: "host", Value: "from-header.example"}}})
	roundTrip(t, h, client, &bhttp.Request{Method: "GET", Scheme: "https", Path: "/"})
	if len(hosts) != 2 || hosts[0] != "from-header.example" || hosts[1] != "gateway.example" {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestGatewayRFC9458Example(t *testing.T) {
	cfg := testConfig()
	cfg.Keys = []KeyConfig{{KeyID: 1, PrivateKey: rfcPrivateKey, Suites: []string{"HKDF-SHA256/AES-128-GCM"}}}
	h := newTestGateway(t, cfg, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.Host != "example.com" || req.URL.Path != "/" {
			t.Errorf("unexpected request %s %s %s", req.Method, req.Host, req.URL)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	encReq := mustHex(t, "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525")
	req := httptest.NewRequest(http.MethodPost, "https://example.com"+DefaultGatewayPath, bytes.NewReader(encReq))
	req.Header.Set("Content-Type", "message/ohttp-req")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// The response nonce is random, so only the length can be checked: 16
	// bytes of nonce, the 6-byte binary response (unlike the RFC example, empty
	// sections are not truncated) and the 16-byte tag.
	if rec.Code != http.StatusOK || rec.Body.Len() != 16+6+16 {
		t.Fatalf("status %d, length %d", rec.Code, rec.Body.Len())
	}
}

func TestRetiredKeyStillAccepted(t *testing.T) {
	cfg := testConfig()
	cfg.Keys = append(cfg.Keys, KeyConfig{KeyID: 9, Seed: testSeed2, Retired: true})
	h := newTestGateway(t, cfg, nil)
	sk, err := hpke.KEMX25519HKDFSHA256.DeriveKeyPair(mustHex(t, testSeed2))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ohttp.NewClient(ohttp.KeyConfig{
		KeyID: 9, KEM: hpke.KEMX25519HKDFSHA256, PublicKey: sk.PublicKey(),
		Suites: []ohttp.SymmetricSuite{{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES256GCM}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := roundTrip(t, h, client, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "a.example", Path: "/"})
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestOuterErrors(t *testing.T) {
	cfg := testConfig()
	cfg.MaxRequestSize = 256
	h := newTestGateway(t, cfg, nil)
	configs := fetchKeyConfigs(t, h, DefaultGatewayPath)
	client, err := ohttp.NewClient(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	valid, _, err := client.EncapsulateRequest(rand.Reader, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	unknownKey := append([]byte{}, valid...)
	unknownKey[0] = 42
	unsupportedSuite := append([]byte{}, valid...)
	unsupportedSuite[4] = 0x03 // HKDF-SHA512 is not advertised by default.
	corrupted := append([]byte{}, valid...)
	corrupted[len(corrupted)-1] ^= 1

	cases := []struct {
		name        string
		contentType string
		body        []byte
		status      int
		problem     string
	}{
		{"missing content type", "", valid, http.StatusUnsupportedMediaType, ""},
		{"wrong content type", "application/octet-stream", valid, http.StatusUnsupportedMediaType, ""},
		{"too large", ohttp.RequestMediaType, make([]byte, 257), http.StatusRequestEntityTooLarge, ""},
		{"malformed", ohttp.RequestMediaType, []byte{1, 2, 3}, http.StatusBadRequest, ""},
		{"unknown key", ohttp.RequestMediaType, unknownKey, http.StatusBadRequest, "key identifier unknown"},
		{"unsupported suite", ohttp.RequestMediaType, unsupportedSuite, http.StatusBadRequest, "unsupported key configuration"},
		{"corrupted", ohttp.RequestMediaType, corrupted, http.StatusBadRequest, "key configuration mismatch"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "https://gateway.example"+DefaultGatewayPath, bytes.NewReader(c.body))
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.status)
			continue
		}
		if c.problem != "" {
			if rec.Header().Get("Content-Type") != "application/problem+json" ||
				!strings.Contains(rec.Body.String(), problemTypeKey) ||
				!strings.Contains(rec.Body.String(), c.problem) {
				t.Errorf("%s: problem = %q %q", c.name, rec.Header().Get("Content-Type"), rec.Body.String())
			}
		}
	}

	// A content type with parameters is accepted.
	req := httptest.NewRequest(http.MethodPost, "https://gateway.example"+DefaultGatewayPath, bytes.NewReader(valid))
	req.Header.Set("Content-Type", "message/ohttp-req; foo=bar")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestInnerErrors(t *testing.T) {
	cfg := testConfig()
	cfg.AllowedTargets = []string{"allowed.example", "*.wild.example", "port.example:8443"}
	h := newTestGateway(t, cfg, nil)
	client := newClient(t, h)

	cases := []struct {
		name   string
		raw    []byte
		msg    *bhttp.Request
		status int
	}{
		{"invalid binary request", []byte{0x01, 0x40, 0xc8}, nil, http.StatusBadRequest},
		{"connect", nil, &bhttp.Request{Method: "CONNECT", Authority: "allowed.example:443"}, http.StatusNotImplemented},
		{"bad scheme", nil, &bhttp.Request{Method: "GET", Scheme: "ftp", Authority: "allowed.example", Path: "/"}, http.StatusBadRequest},
		{"bad path", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "allowed.example", Path: "relative"}, http.StatusBadRequest},
		{"asterisk with GET", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "allowed.example", Path: "*"}, http.StatusBadRequest},
		{"bad method", nil, &bhttp.Request{Method: "G ET", Scheme: "https", Authority: "allowed.example", Path: "/"}, http.StatusBadRequest},
		{"bad authority", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "user@allowed.example", Path: "/"}, http.StatusBadRequest},
		{"bad field name", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "allowed.example", Path: "/", Header: []bhttp.Field{{Name: "bad name", Value: "x"}}}, http.StatusBadRequest},
		{"bad field value", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "allowed.example", Path: "/", Header: []bhttp.Field{{Name: "x", Value: "a\r\nb"}}}, http.StatusBadRequest},
		{"expect continue", nil, &bhttp.Request{Method: "POST", Scheme: "https", Authority: "allowed.example", Path: "/", Header: []bhttp.Field{{Name: "expect", Value: "100-continue"}}}, http.StatusExpectationFailed},
		{"disallowed target", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "evil.example", Path: "/"}, http.StatusForbidden},
		{"disallowed port", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "port.example:9999", Path: "/"}, http.StatusForbidden},
		{"allowed with port", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "allowed.example:8080", Path: "/"}, http.StatusTeapot},
		{"allowed wildcard", nil, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "a.b.WILD.example", Path: "/"}, http.StatusTeapot},
		{"allowed exact port", nil, &bhttp.Request{Method: "GET", Scheme: "http", Authority: "port.example:8443", Path: "/"}, http.StatusTeapot},
		{"options asterisk", nil, &bhttp.Request{Method: "OPTIONS", Scheme: "https", Authority: "allowed.example", Path: "*"}, http.StatusTeapot},
	}
	for _, c := range cases {
		raw := c.raw
		if c.msg != nil {
			var err error
			if raw, err = c.msg.Marshal(); err != nil {
				t.Fatal(err)
			}
		}
		encReq, clientCtx, err := client.EncapsulateRequest(rand.Reader, raw)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://gateway.example"+DefaultGatewayPath, bytes.NewReader(encReq))
		req.Header.Set("Content-Type", ohttp.RequestMediaType)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		// Errors after decapsulation are always encapsulated.
		if rec.Code != http.StatusOK {
			t.Errorf("%s: outer status = %d", c.name, rec.Code)
			continue
		}
		binaryResponse, err := clientCtx.DecapsulateResponse(rec.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		resp, err := bhttp.UnmarshalResponse(binaryResponse)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != c.status {
			t.Errorf("%s: inner status = %d, want %d", c.name, resp.StatusCode, c.status)
		}
	}
}

func TestResponseLimitsAndPadding(t *testing.T) {
	cfg := testConfig()
	cfg.MaxResponseSize = 10
	cfg.PaddingBlockSize = 64
	size := 0
	h := newTestGateway(t, cfg, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusEarlyHints) // Informational responses are dropped.
		_, _ = rw.Write(bytes.Repeat([]byte("a"), size))
		_, _ = rw.Write(bytes.Repeat([]byte("b"), size))
	}))
	client := newClient(t, h)
	msg := &bhttp.Request{Method: "GET", Scheme: "https", Authority: "a.example", Path: "/"}

	size = 5
	resp, raw := roundTrip(t, h, client, msg)
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "aaaaabbbbb" {
		t.Fatalf("response = %d %q", resp.StatusCode, resp.Body)
	}
	if len(raw)%64 != 0 {
		t.Fatalf("binary response length %d is not padded to 64", len(raw))
	}

	size = 6
	resp, _ = roundTrip(t, h, client, msg)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestAbortedTarget(t *testing.T) {
	h := newTestGateway(t, testConfig(), http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	resp, _ := roundTrip(t, h, newClient(t, h), &bhttp.Request{Method: "GET", Scheme: "https", Authority: "a.example", Path: "/"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestForwardURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		switch req.URL.Path {
		case "/base/slow":
			time.Sleep(300 * time.Millisecond)
		case "/base/redirect":
			http.Redirect(rw, req, "/elsewhere", http.StatusFound)
			return
		case "/base/big":
			_, _ = rw.Write(bytes.Repeat([]byte("x"), 2048))
			return
		}
		rw.Header().Set("X-Seen-Host", req.Host)
		rw.Header().Set("X-Seen-Uri", req.URL.RequestURI())
		rw.Header().Set("X-Seen-Header", req.Header.Get("X-Test"))
		rw.WriteHeader(http.StatusAccepted)
		_, _ = rw.Write(body)
	}))
	defer upstream.Close()

	cfg := testConfig()
	cfg.ForwardURL = upstream.URL + "/base/"
	cfg.ForwardTimeout = "100ms"
	cfg.MaxResponseSize = 1024
	nextCalled := false
	h := newTestGateway(t, cfg, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { nextCalled = true }))
	client := newClient(t, h)

	resp, _ := roundTrip(t, h, client, &bhttp.Request{
		Method: "PUT", Scheme: "https", Authority: "target.example", Path: "/echo?x=1",
		Header: []bhttp.Field{{Name: "x-test", Value: "yes"}},
		Body:   []byte("payload"),
	})
	header := bhttp.HeaderFromFields(resp.Header)
	if resp.StatusCode != http.StatusAccepted || string(resp.Body) != "payload" ||
		header.Get("X-Seen-Host") != "target.example" || header.Get("X-Seen-Uri") != "/base/echo?x=1" || header.Get("X-Seen-Header") != "yes" {
		t.Fatalf("response = %d %q %v", resp.StatusCode, resp.Body, header)
	}
	if nextCalled {
		t.Fatal("next handler must not be called in forward mode")
	}

	expectations := map[string]int{"/slow": http.StatusGatewayTimeout, "/redirect": http.StatusFound, "/big": http.StatusBadGateway}
	for path, status := range expectations {
		resp, _ = roundTrip(t, h, client, &bhttp.Request{Method: "GET", Scheme: "https", Authority: "target.example", Path: path})
		if resp.StatusCode != status {
			t.Errorf("%s: status = %d, want %d", path, resp.StatusCode, status)
		}
	}

	// Unreachable upstream.
	cfg.ForwardURL = "http://127.0.0.1:1"
	h = newTestGateway(t, cfg, nil)
	resp, _ = roundTrip(t, h, newClient(t, h), &bhttp.Request{Method: "GET", Scheme: "https", Authority: "target.example", Path: "/"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	if err := os.WriteFile(file, []byte(rfcPrivateKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Keys = []KeyConfig{{KeyID: 1, PrivateKeyFile: file}}
	h := newTestGateway(t, cfg, nil)
	configs := fetchKeyConfigs(t, h, DefaultGatewayPath)
	// Public key from the RFC 9458 example key configuration.
	if hex.EncodeToString(configs[0].PublicKey.Bytes()) != "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155" {
		t.Fatal("public key mismatch")
	}
}

func TestInvalidConfigs(t *testing.T) {
	cases := map[string]func(*Config){
		"nil keys":            func(c *Config) { c.Keys = nil },
		"relative path":       func(c *Config) { c.GatewayPath = "ohttp" },
		"relative keys path":  func(c *Config) { c.KeysPath = "keys" },
		"same paths":          func(c *Config) { c.KeysPath = c.GatewayPath },
		"zero request size":   func(c *Config) { c.MaxRequestSize = 0 },
		"zero response size":  func(c *Config) { c.MaxResponseSize = 0 },
		"negative padding":    func(c *Config) { c.PaddingBlockSize = -1 },
		"negative max age":    func(c *Config) { c.KeysCacheMaxAge = -1 },
		"bad target":          func(c *Config) { c.AllowedTargets = []string{"*."} },
		"bad target path":     func(c *Config) { c.AllowedTargets = []string{"a.example/path"} },
		"bad forward url":     func(c *Config) { c.ForwardURL = "ftp://x" },
		"bad forward timeout": func(c *Config) { c.ForwardURL = "http://x"; c.ForwardTimeout = "soon" },
		"zero forward timeout": func(c *Config) {
			c.ForwardURL = "http://x"
			c.ForwardTimeout = "0s"
		},
		"key id range":    func(c *Config) { c.Keys[0].KeyID = 256 },
		"duplicate ids":   func(c *Config) { c.Keys = append(c.Keys, KeyConfig{KeyID: 1, Seed: testSeed2}) },
		"all retired":     func(c *Config) { c.Keys[0].Retired = true },
		"no key material": func(c *Config) { c.Keys[0].Seed = "" },
		"two sources":     func(c *Config) { c.Keys[0].PrivateKey = rfcPrivateKey },
		"short seed":      func(c *Config) { c.Keys[0].Seed = "0011" },
		"bad seed":        func(c *Config) { c.Keys[0].Seed = "%%%" },
		"bad kem":         func(c *Config) { c.Keys[0].KEM = "X448" },
		"bad suite":       func(c *Config) { c.Keys[0].Suites = []string{"HKDF-SHA256"} },
		"bad kdf":         func(c *Config) { c.Keys[0].Suites = []string{"SHA1/AES-128-GCM"} },
		"chacha":          func(c *Config) { c.Keys[0].Suites = []string{"HKDF-SHA256/ChaCha20Poly1305"} },
		"bad private key": func(c *Config) { c.Keys[0] = KeyConfig{PrivateKey: "abcd"} },
		"wrong curve key": func(c *Config) { c.Keys[0] = KeyConfig{KEM: "P-384", PrivateKey: rfcPrivateKey} },
		"missing file":    func(c *Config) { c.Keys[0] = KeyConfig{PrivateKeyFile: "/nonexistent/key"} },
	}
	for name, mutate := range cases {
		cfg := testConfig()
		mutate(cfg)
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := New(context.Background(), http.NotFoundHandler(), nil, "test"); err == nil {
		t.Error("nil config: expected an error")
	}
}

func TestKeyMaterialEncodings(t *testing.T) {
	raw := mustHex(t, rfcPrivateKey)
	for _, value := range []string{
		rfcPrivateKey,
		" " + strings.ToUpper(rfcPrivateKey) + "\n",
		"PBaJdWdLL6jkZZcLecjc8J8cdBYmSAvUxhYvxbapjho=",
		"PBaJdWdLL6jkZZcLecjc8J8cdBYmSAvUxhYvxbapjho",
	} {
		got, err := decodeKeyMaterial(value)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("decode %q = %x, %v", value, got, err)
		}
	}
	for _, name := range []string{"X25519", "p-256", "P_384", "DHKEM(P-521, HKDF-SHA512)", "0x0020"} {
		if _, err := ohttp.ParseKEM(name); err != nil {
			t.Errorf("ParseKEM(%q): %v", name, err)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
