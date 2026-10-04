package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	ohttpgo "github.com/chris-wood/ohttp-go"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/bhttp"
	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/ohttp"
)

const gatewayPath = "/.well-known/ohttp-gateway"

// do sends a plain (non-oblivious) request to Traefik for the given virtual host.
func do(t *testing.T, method, host, path, contentType string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, stack.webURL+path, bytes.NewReader(body)) //nolint:noctx // Test helper.
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// Outer headers, as a relay could add them, must never reach the target.
	req.Header.Set("X-Relay-Leak", "outer-header")
	resp, err := stack.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, respBody
}

// keyConfigEntries fetches application/ohttp-keys and splits it into the raw
// key configurations.
func keyConfigEntries(t *testing.T, host, path string) [][]byte {
	t.Helper()
	resp, body := do(t, http.MethodGet, host, path, "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ohttp.KeysMediaType {
		t.Fatalf("GET %s%s: %d %q", host, path, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var entries [][]byte
	for len(body) > 0 {
		if len(body) < 2 {
			t.Fatal("truncated key configuration list")
		}
		n := int(binary.BigEndian.Uint16(body))
		if len(body) < 2+n {
			t.Fatal("truncated key configuration")
		}
		entries = append(entries, body[2:2+n])
		body = body[2+n:]
	}
	return entries
}

// interopRoundTrip sends req through the gateway using the independent
// github.com/chris-wood/ohttp-go client implementation.
func interopRoundTrip(t *testing.T, host string, config []byte, req *http.Request) *http.Response {
	t.Helper()
	publicConfig, err := ohttpgo.UnmarshalPublicConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	client := ohttpgo.NewDefaultClient(publicConfig)
	binaryRequest := ohttpgo.BinaryRequest(*req)
	encoded, err := binaryRequest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encReq, reqCtx, err := client.EncapsulateRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := do(t, http.MethodPost, host, gatewayPath, ohttp.RequestMediaType, encReq.Marshal())
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ohttp.ResponseMediaType {
		t.Fatalf("outer response: %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	encResp, err := ohttpgo.UnmarshalEncapsulatedResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	binaryResponse, err := reqCtx.DecapsulateResponse(encResp)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := ohttpgo.UnmarshalBinaryResponse(binaryResponse)
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

// nativeRoundTrip sends msg through the gateway using this repository's
// client implementation, which supports every configured algorithm.
func nativeRoundTrip(t *testing.T, host string, config ohttp.KeyConfig, msg *bhttp.Request) (*bhttp.Response, int) {
	t.Helper()
	client, err := ohttp.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encReq, clientCtx, err := client.EncapsulateRequest(rand.Reader, encoded)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := do(t, http.MethodPost, host, gatewayPath, ohttp.RequestMediaType, encReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("outer response: %d %s", resp.StatusCode, body)
	}
	binaryResponse, err := clientCtx.DecapsulateResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := bhttp.UnmarshalResponse(binaryResponse)
	if err != nil {
		t.Fatal(err)
	}
	return inner, len(binaryResponse)
}

func decodeEcho(t *testing.T, body []byte) echoResponse {
	t.Helper()
	var echo echoResponse
	if err := json.Unmarshal(body, &echo); err != nil {
		t.Fatalf("invalid echo body %q: %v", body, err)
	}
	return echo
}

func TestKeyConfigurationDiscovery(t *testing.T) {
	entries := keyConfigEntries(t, "gateway.localhost", gatewayPath)
	if len(entries) != 1 {
		t.Fatalf("got %d key configurations, the retired key must not be advertised", len(entries))
	}
	// The same document is served on keysPath.
	if alt := keyConfigEntries(t, "gateway.localhost", "/ohttp-keys"); len(alt) != 1 || !bytes.Equal(alt[0], entries[0]) {
		t.Fatal("keysPath serves a different key configuration")
	}
	configs, err := ohttp.ParseKeyConfigs(append([]byte{0, byte(len(entries[0]))}, entries[0]...))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := hpke.KEMX25519HKDFSHA256.DeriveKeyPair(mustHex(t, seed1))
	if err != nil {
		t.Fatal(err)
	}
	if configs[0].KeyID != 1 || !configs[0].PublicKey.Equal(sk.PublicKey()) {
		t.Fatalf("unexpected key configuration %+v", configs[0])
	}
}

// TestInteropOhttpGo validates the gateway against an independent OHTTP
// client implementation.
func TestInteropOhttpGo(t *testing.T) {
	config := keyConfigEntries(t, "gateway.localhost", gatewayPath)[0]

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/resource", strings.NewReader(`{"hello":"oblivious"}`)) //nolint:noctx // Encapsulated request.
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Inner", "inner-header")
	req.Header.Set("X-Forwarded-For", "6.6.6.6")

	inner := interopRoundTrip(t, "gateway.localhost", config, req)
	body, err := io.ReadAll(inner.Body)
	if err != nil {
		t.Fatal(err)
	}
	if inner.StatusCode != http.StatusOK || rawHeader(inner.Header, "x-backend") != "echo" {
		t.Fatalf("inner response: %d %v", inner.StatusCode, inner.Header)
	}
	echo := decodeEcho(t, body)
	switch {
	case echo.Method != http.MethodPost:
		t.Errorf("method = %s", echo.Method)
	case echo.Host != "api.example.com":
		t.Errorf("host = %s", echo.Host)
	case echo.URI != "/v1/resource":
		t.Errorf("uri = %s", echo.URI)
	case echo.Body != `{"hello":"oblivious"}`:
		t.Errorf("body = %s", echo.Body)
	case echo.Header.Get("X-Inner") != "inner-header" || echo.Header.Get("Content-Type") != "application/json":
		t.Errorf("inner headers missing: %v", echo.Header)
	case echo.Header.Get("X-Relay-Leak") != "":
		t.Errorf("outer header leaked to the target: %v", echo.Header)
	case strings.Contains(echo.Header.Get("X-Forwarded-For"), "6.6.6.6"):
		t.Errorf("client-supplied X-Forwarded-For reached the target: %v", echo.Header)
	}
}

func TestNativeClientWithQueryAndStatus(t *testing.T) {
	configs, err := ohttp.ParseKeyConfigs(lengthPrefixed(keyConfigEntries(t, "gateway.localhost", gatewayPath)))
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := nativeRoundTrip(t, "gateway.localhost", configs[0], &bhttp.Request{
		Method: http.MethodDelete, Scheme: "https", Authority: "api.example.com", Path: "/items/42?status=404&x=y",
	})
	if inner.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", inner.StatusCode)
	}
	echo := decodeEcho(t, inner.Body)
	if echo.Method != http.MethodDelete || echo.URI != "/items/42?status=404&x=y" {
		t.Fatalf("echo = %+v", echo)
	}

	// Large request and response bodies.
	payload := strings.Repeat("p", 200000)
	inner, _ = nativeRoundTrip(t, "gateway.localhost", configs[0], &bhttp.Request{
		Method: http.MethodPut, Scheme: "https", Authority: "api.example.com", Path: "/upload",
		Body: []byte(payload),
	})
	if echo := decodeEcho(t, inner.Body); echo.Body != payload {
		t.Fatalf("large body mismatch (%d bytes)", len(echo.Body))
	}
	inner, _ = nativeRoundTrip(t, "gateway.localhost", configs[0], &bhttp.Request{
		Method: http.MethodGet, Scheme: "https", Authority: "api.example.com", Path: "/download?size=500000",
	})
	if len(inner.Body) != 500000 {
		t.Fatalf("response body = %d bytes", len(inner.Body))
	}
}

func TestP256KeyAndPadding(t *testing.T) {
	configs, err := ohttp.ParseKeyConfigs(lengthPrefixed(keyConfigEntries(t, "p256.localhost", gatewayPath)))
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].KEM != hpke.KEMP256HKDFSHA256 || configs[0].KeyID != 7 ||
		configs[0].Suites[0] != (ohttp.SymmetricSuite{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES256GCM}) {
		t.Fatalf("unexpected configuration %+v", configs)
	}
	inner, size := nativeRoundTrip(t, "p256.localhost", configs[0], &bhttp.Request{
		Method: http.MethodGet, Scheme: "https", Authority: "p256.example", Path: "/",
	})
	if inner.StatusCode != http.StatusOK || decodeEcho(t, inner.Body).Host != "p256.example" {
		t.Fatalf("inner response: %d %s", inner.StatusCode, inner.Body)
	}
	if size%256 != 0 {
		t.Fatalf("binary response of %d bytes is not padded to 256", size)
	}

	// The independent client also handles P-256 and padded responses.
	req, err := http.NewRequest(http.MethodGet, "https://p256.example/interop", nil) //nolint:noctx // Encapsulated request.
	if err != nil {
		t.Fatal(err)
	}
	resp := interopRoundTrip(t, "p256.localhost", keyConfigEntries(t, "p256.localhost", gatewayPath)[0], req)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || decodeEcho(t, body).URI != "/interop" {
		t.Fatalf("interop response: %d %s", resp.StatusCode, body)
	}
}

// TestForwardMode checks that decapsulated requests are routed by Traefik and
// that allowedTargets is enforced.
func TestForwardMode(t *testing.T) {
	config := keyConfigEntries(t, "forward.localhost", gatewayPath)[0]

	req, err := http.NewRequest(http.MethodGet, "https://app.localhost/routed", nil) //nolint:noctx // Encapsulated request.
	if err != nil {
		t.Fatal(err)
	}
	inner := interopRoundTrip(t, "forward.localhost", config, req)
	body, _ := io.ReadAll(inner.Body)
	if inner.StatusCode != http.StatusOK || rawHeader(inner.Header, "x-routed-by") != "app-router" {
		t.Fatalf("inner response: %d %v %s", inner.StatusCode, inner.Header, body)
	}
	if echo := decodeEcho(t, body); echo.Host != "app.localhost" || echo.URI != "/routed" {
		t.Fatalf("echo = %+v", echo)
	}

	req, err = http.NewRequest(http.MethodGet, "https://not-allowed.localhost/", nil) //nolint:noctx // Encapsulated request.
	if err != nil {
		t.Fatal(err)
	}
	if inner = interopRoundTrip(t, "forward.localhost", config, req); inner.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed target: status %d", inner.StatusCode)
	}
}

func TestRetiredKeyStillDecrypts(t *testing.T) {
	sk, err := hpke.KEMX25519HKDFSHA256.DeriveKeyPair(mustHex(t, seed2))
	if err != nil {
		t.Fatal(err)
	}
	config := ohttp.KeyConfig{
		KeyID: 2, KEM: hpke.KEMX25519HKDFSHA256, PublicKey: sk.PublicKey(),
		Suites: []ohttp.SymmetricSuite{{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM}},
	}
	inner, _ := nativeRoundTrip(t, "gateway.localhost", config, &bhttp.Request{
		Method: http.MethodGet, Scheme: "https", Authority: "api.example.com", Path: "/retired",
	})
	if inner.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", inner.StatusCode)
	}
}

func TestOuterErrors(t *testing.T) {
	entries := keyConfigEntries(t, "gateway.localhost", gatewayPath)
	configs, err := ohttp.ParseKeyConfigs(lengthPrefixed(entries))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ohttp.NewClient(configs[0])
	if err != nil {
		t.Fatal(err)
	}
	encReq, _, err := client.EncapsulateRequest(rand.Reader, []byte{0})
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := do(t, http.MethodPost, "gateway.localhost", gatewayPath, "text/plain", encReq)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type: %d", resp.StatusCode)
	}

	unknown := append([]byte{}, encReq...)
	unknown[0] = 200
	resp, body := do(t, http.MethodPost, "gateway.localhost", gatewayPath, ohttp.RequestMediaType, unknown)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Type") != "application/problem+json" ||
		!strings.Contains(string(body), "https://iana.org/assignments/http-problem-types#ohttp-key") {
		t.Errorf("unknown key: %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	resp, _ = do(t, http.MethodPut, "gateway.localhost", gatewayPath, "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", resp.StatusCode)
	}

	resp, _ = do(t, http.MethodPost, "gateway.localhost", gatewayPath, ohttp.RequestMediaType, make([]byte, 2<<20))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized request: %d", resp.StatusCode)
	}
}

// TestPassThrough checks that other paths reach the service untouched.
func TestPassThrough(t *testing.T) {
	resp, body := do(t, http.MethodGet, "gateway.localhost", "/plain?x=1", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if echo := decodeEcho(t, body); echo.URI != "/plain?x=1" || echo.Header.Get("X-Relay-Leak") != "outer-header" {
		t.Fatalf("echo = %+v", echo)
	}
}

// rawHeader reads a header from ohttp-go responses, which keep the lowercase
// binary HTTP field names as map keys instead of canonicalizing them.
func rawHeader(h http.Header, name string) string {
	if values := h[name]; len(values) > 0 {
		return values[0]
	}
	return ""
}

func lengthPrefixed(entries [][]byte) []byte {
	var out []byte
	for _, e := range entries {
		out = binary.BigEndian.AppendUint16(out, uint16(len(e)))
		out = append(out, e...)
	}
	return out
}
