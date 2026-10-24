package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	handler "github.com/group-project/authentication/internal/handler/http"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/router"
	"github.com/group-project/authentication/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

func machinePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	raw := os.Getenv("AUTH_MACHINE_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("requires isolated machine fixture")
	}
	u, err := url.Parse(raw)
	run := os.Getenv("AUTH_MACHINE_TEST_RUN_ID")
	if err != nil || u.Hostname() != "127.0.0.1" || u.Port() != os.Getenv("AUTH_MACHINE_TEST_PORT") || u.Path != "/auth_machine_test" || u.User.Username() != "auth_machine_fixture" || !strings.HasPrefix(run, "auth-machine-test-") {
		t.Fatal("unsafe fixture configuration")
	}
	p, err := pgxpool.New(context.Background(), raw)
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	t.Cleanup(p.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var marker string
	if err := p.QueryRow(ctx, "SELECT current_setting('auth.fixture_id')").Scan(&marker); err != nil {
		t.Fatal("fixture marker query unavailable")
	}
	if marker != run {
		t.Fatal("fixture marker mismatch")
	}
	return p
}
func TestMachineLifecycleAndIssuerContract(t *testing.T) {
	p := machinePool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("key generation")
	}
	repo := postgres.NewMachineRepository(p)
	s, err := service.NewMachineService(repo, key, "erp-auth", 5*time.Minute)
	if err != nil {
		t.Fatal("service construction")
	}
	id, err := s.Create(ctx)
	if err != nil {
		t.Fatal("create")
	}
	cred, err := s.Rotate(ctx, id, 90*24*time.Hour)
	if err != nil {
		t.Fatal("rotate")
	}
	if _, err = s.Issue(ctx, id.String(), cred.Secret); err == nil {
		t.Fatal("disabled identity issued")
	}
	if s.SetEnabled(ctx, id, true) != nil {
		t.Fatal("enable")
	}
	if _, err = s.Issue(ctx, id.String(), cred.Secret); err == nil {
		t.Fatal("ungranted issued")
	}
	if s.SetGrant(ctx, id, true) != nil {
		t.Fatal("grant")
	}
	var logs bytes.Buffer
	oldWriter := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = oldWriter })
	h := handler.NewMachineHandler(s, zerolog.New(&logs))
	r := router.NewRouter(nil, nil, nil, p).WithMachineHandler(h).Router()
	server := httptest.NewTLSServer(r)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	form := "grant_type=client_credentials&audience=" + domain.MachineAudience + "&scope=" + url.QueryEscape(domain.MachinePermission)
	call := func(body, password string) (int, string) {
		req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v1/auth/service-token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id.String(), password)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("HTTP issuance failed")
		}
		defer res.Body.Close()
		if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
			t.Fatal("cache headers missing")
		}
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if json.NewDecoder(res.Body).Decode(&out) != nil {
			t.Fatal("invalid response")
		}
		return res.StatusCode, out.AccessToken
	}
	status, token := call(form, cred.Secret)
	if status != 200 || token == "" {
		t.Fatal("HTTP issuance rejected")
	}
	human, err := helper.NewJWTManager(key, "erp-auth", "erp-api", 15*time.Minute)
	if err != nil {
		t.Fatal("human manager")
	}
	if _, err = human.Validate(token); err == nil {
		t.Fatal("Auth human boundary accepted machine")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("public key")
	}
	payload, _ := json.Marshal(struct {
		Token     string
		PublicKey string
	}{token, base64.StdEncoding.EncodeToString(der)})
	catalog, err := filepath.Abs("../../../Catalog-Service")
	if err != nil {
		t.Fatal("catalog path")
	}
	// go test does not forward stdin to its test binary. Compile a temporary
	// binary, then feed the real issued token directly through its stdin pipe.
	binary := filepath.Join(t.TempDir(), "catalog-machine-contract.exe")
	compile := exec.CommandContext(ctx, "go", "-C", catalog, "test", "-c", "-o", binary, "./internal/security")
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("Catalog contract compilation failed: %s", output)
	}
	cmd := exec.CommandContext(ctx, binary, "-test.timeout=30s", "-test.run=^TestMachineIssuerContract$")
	cmd.Env = append(os.Environ(), "AUTH_MACHINE_CONTRACT_STDIN=1")
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Only this controlled child test receives a token, via stdin. Redact
		// that value defensively before reporting compiler/assertion diagnostics.
		safe := strings.ReplaceAll(string(output), token, "[redacted-token]")
		t.Fatalf("Catalog contract subprocess failed: %s", safe)
	}
	if !bytes.Contains(output, []byte("PASS")) {
		t.Fatal("Catalog contract result missing")
	}
	t.Log("actual TLS HTTP issuer to Catalog verifier passed")
	for _, bad := range []string{"", uuid.NewString() + "." + strings.Repeat("A", 43), cred.Secret + "x"} {
		if st, _ := call(form, bad); st != 401 {
			t.Fatal("bad credential accepted")
		}
	}
	for _, bad := range []string{form + "&scope=x", strings.Replace(form, "client_credentials", "password", 1), strings.Replace(form, domain.MachineAudience, "erp-api", 1), form + "&client_secret=x"} {
		if st, _ := call(bad, cred.Secret); st != 400 {
			t.Fatal("bad form accepted")
		}
	}
	second, err := s.Rotate(ctx, id, 48*time.Hour)
	if err != nil {
		t.Fatal("second rotation")
	}
	if _, err = s.Issue(ctx, id.String(), cred.Secret); err != nil {
		t.Fatal("overlap not usable")
	}
	var remaining float64
	if p.QueryRow(ctx, "SELECT extract(epoch from expires_at-clock_timestamp()) FROM machine_credentials WHERE id=$1", cred.ID).Scan(&remaining) != nil || remaining > 86400 {
		t.Fatal("overlap exceeds 24h")
	}
	third, err := s.Rotate(ctx, id, 48*time.Hour)
	if err != nil {
		t.Fatal("third rotation")
	}
	if _, err = s.Issue(ctx, id.String(), cred.Secret); err == nil {
		t.Fatal("old overlap retained")
	}
	// Revoking the credential must not be mistaken for online JWT revocation.
	verifyAgain := exec.CommandContext(ctx, binary, "-test.timeout=30s", "-test.run=^TestMachineIssuerContract$")
	verifyAgain.Env = append(os.Environ(), "AUTH_MACHINE_CONTRACT_STDIN=1")
	verifyAgain.Stdin = bytes.NewReader(payload)
	if output, err := verifyAgain.CombinedOutput(); err != nil || !bytes.Contains(output, []byte("PASS")) {
		t.Fatal("issued JWT unexpectedly revoked with credential")
	}
	if _, err = s.Issue(ctx, id.String(), second.Secret); err != nil {
		t.Fatal("latest overlap removed")
	}
	if s.Revoke(ctx, id, second.ID) != nil {
		t.Fatal("revoke")
	}
	if _, err = s.Issue(ctx, id.String(), second.Secret); err == nil {
		t.Fatal("revoked issued")
	}
	if s.SetGrant(ctx, id, false) != nil {
		t.Fatal("remove grant")
	}
	if _, err = s.Issue(ctx, id.String(), third.Secret); err == nil {
		t.Fatal("removed grant issued")
	}
	if s.SetGrant(ctx, id, true) != nil {
		t.Fatal("restore grant")
	}
	if _, err = p.Exec(ctx, "UPDATE machine_credentials SET created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 day' WHERE id=$1", third.ID); err != nil {
		t.Fatal("expire fixture")
	}
	if _, err = s.Issue(ctx, id.String(), third.Secret); err == nil {
		t.Fatal("expired issued")
	}
	if _, err = s.Rotate(ctx, id, domain.MaxCredentialAge+time.Second); err == nil {
		t.Fatal("overlong credential accepted")
	}
	for _, secret := range []string{cred.Secret, second.Secret, third.Secret, token} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("secret in captured logs")
		}
	}
	var count int
	if p.QueryRow(ctx, "SELECT count(*) FROM machine_credentials WHERE machine_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()", id).Scan(&count) != nil || count > 2 {
		t.Fatal("credential bound")
	}
}

func TestMachineConcurrentLifecycle(t *testing.T) {
	p := machinePool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := service.NewMachineService(postgres.NewMachineRepository(p), key, "erp-auth", time.Minute)
	id, err := s.Create(ctx)
	if err != nil {
		t.Fatal("create")
	}
	if s.SetEnabled(ctx, id, true) != nil || s.SetGrant(ctx, id, true) != nil {
		t.Fatal("setup")
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-start:
			case <-ctx.Done():
				results <- ctx.Err()
				return
			}
			_, err := s.Rotate(ctx, id, time.Hour)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent rotation failed")
		}
	}
	var count int
	if p.QueryRow(ctx, "SELECT count(*) FROM machine_credentials WHERE machine_id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()", id).Scan(&count) != nil || count != 2 {
		t.Fatal("concurrent rotation invariant")
	}
	// Hold the same row lock used by issuance, commit disable, then observe the
	// blocked issuance recheck the updated state after acquiring its lock.
	cred, err := s.Rotate(ctx, id, time.Hour)
	if err != nil {
		t.Fatal("credential")
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal("begin")
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT id FROM machine_identities WHERE id=$1 FOR UPDATE", id); err != nil {
		t.Fatal("lock")
	}
	done := make(chan error, 1)
	go func() { _, err := s.Issue(ctx, id.String(), cred.Secret); done <- err }()
	if _, err = tx.Exec(ctx, "UPDATE machine_identities SET enabled=false WHERE id=$1", id); err != nil {
		t.Fatal("disable")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit")
	}
	if err := <-done; err == nil {
		t.Fatal("disabled issuance raced")
	}
}
