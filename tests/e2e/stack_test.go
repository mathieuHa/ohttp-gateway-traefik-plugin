package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Key material shared by the Traefik configuration and the tests.
const (
	seed1 = "8a4f1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"
	seed2 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	// A valid P-256 scalar, written to a file to exercise privateKeyFile.
	p256Key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
)

// stack is the Traefik + backend environment shared by all tests.
var stack struct {
	webURL string
	client *http.Client
}

// TestMain starts a backend and a Traefik binary loading the plugin from the
// repository as a local plugin. TRAEFIK_BIN must point to the Traefik binary;
// the suite is skipped otherwise (see run.sh).
func TestMain(m *testing.M) {
	traefikBin := os.Getenv("TRAEFIK_BIN")
	if traefikBin == "" {
		fmt.Println("TRAEFIK_BIN is not set, skipping the e2e suite (use tests/e2e/run.sh)")
		os.Exit(0)
	}
	code, err := run(m, traefikBin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup failed:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M, traefikBin string) (int, error) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	backendServer := &http.Server{Handler: http.HandlerFunc(echoHandler), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = backendServer.Serve(backend) }()
	defer func() { _ = backendServer.Close() }()

	webPort, err := freePort()
	if err != nil {
		return 0, err
	}
	workDir, err := os.MkdirTemp("", "ohttp-e2e-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	if err := prepareWorkDir(workDir, webPort, backend.Addr().(*net.TCPAddr).Port); err != nil {
		return 0, err
	}

	logPath := filepath.Join(workDir, "traefik.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = logFile.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, traefikBin, "--configfile=traefik.yml")
	cmd.Dir = workDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	}()

	stack.webURL = "http://127.0.0.1:" + strconv.Itoa(webPort)
	stack.client = &http.Client{Timeout: 10 * time.Second}
	if err := waitReady(stack.webURL+"/ping", 90*time.Second); err != nil {
		dumpLog(logPath)
		return 0, err
	}
	if err := checkPluginLoaded(logPath); err != nil {
		dumpLog(logPath)
		return 0, err
	}

	code := m.Run()
	if code != 0 || os.Getenv("E2E_VERBOSE") != "" {
		dumpLog(logPath)
	}
	return code, nil
}

func prepareWorkDir(workDir string, webPort, backendPort int) error {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		return err
	}
	// Traefik loads local plugins from ./plugins-local/src/<moduleName>.
	pluginDir := filepath.Join(workDir, "plugins-local", "src", "github.com", "mathieuHa")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return err
	}
	if err := os.Symlink(repoRoot, filepath.Join(pluginDir, "ohttp-gateway-traefik-plugin")); err != nil {
		return err
	}

	keyFile := filepath.Join(workDir, "p256.key")
	if err := os.WriteFile(keyFile, []byte(p256Key+"\n"), 0o600); err != nil {
		return err
	}

	replacer := strings.NewReplacer(
		"@@WEB_PORT@@", strconv.Itoa(webPort),
		"@@BACKEND_PORT@@", strconv.Itoa(backendPort),
		"@@SEED_1@@", seed1,
		"@@SEED_2@@", seed2,
		"@@P256_KEY_FILE@@", keyFile,
	)
	for _, name := range []string{"traefik.yml", "dynamic.yml"} {
		content, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(replacer.Replace(string(content))), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx // Readiness probe.
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("traefik not ready after %s", timeout)
}

// checkPluginLoaded waits until every router using the plugin answers on its
// gateway path: /ping can be up before the dynamic configuration is applied.
func checkPluginLoaded(logPath string) error {
	deadline := time.Now().Add(60 * time.Second)
	hosts := []string{"gateway.localhost", "p256.localhost", "forward.localhost"}
	for time.Now().Before(deadline) {
		if content, _ := os.ReadFile(logPath); strings.Contains(string(content), "Plugins are disabled") {
			return errors.New("traefik disabled the plugin, see the Traefik log")
		}
		ready := 0
		for _, host := range hosts {
			req, err := http.NewRequest(http.MethodGet, stack.webURL+"/.well-known/ohttp-gateway", nil) //nolint:noctx // Readiness probe.
			if err != nil {
				return err
			}
			req.Host = host
			resp, err := stack.client.Do(req)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == "application/ohttp-keys" {
					ready++
				}
			}
		}
		if ready == len(hosts) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("gateway routers did not become ready, see the Traefik log")
}

func dumpLog(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	fmt.Println("===== traefik.log =====")
	fmt.Println(string(content))
}

// echoResponse is what the backend returns: a description of the request it
// received. Query parameters control the response: status, size (body of
// "x"), header (adds X-Echo-Header).
type echoResponse struct {
	Method string      `json:"method"`
	Host   string      `json:"host"`
	URI    string      `json:"uri"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

func echoHandler(rw http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	query := req.URL.Query()
	if size := query.Get("size"); size != "" {
		n, _ := strconv.Atoi(size)
		rw.Header().Set("Content-Type", "application/octet-stream")
		_, _ = rw.Write([]byte(strings.Repeat("x", n)))
		return
	}
	status := http.StatusOK
	if s := query.Get("status"); s != "" {
		status, _ = strconv.Atoi(s)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("X-Backend", "echo")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(echoResponse{
		Method: req.Method,
		Host:   req.Host,
		URI:    req.RequestURI,
		Header: req.Header,
		Body:   string(body),
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
