package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReservationMachineAuthority(t *testing.T) {
	target, run := os.Getenv("RESERVATION_AUTH_DATABASE_URL"), os.Getenv("RESERVATION_AUTH_RUN_ID")
	if target == "" && run == "" {
		t.Skip("requires owned reservation Auth fixture")
	}
	if !strings.HasPrefix(run, "inventory-stock-test-") {
		t.Fatal("invalid fixture identity")
	}
	if _, err := uuid.Parse(strings.TrimPrefix(run, "inventory-stock-test-")); err != nil {
		t.Fatal("invalid run identity")
	}
	cfg, err := pgxpool.ParseConfig(target)
	if err != nil || cfg.ConnConfig.Host != "127.0.0.1" || cfg.ConnConfig.Database != "auth_reservation_test" || cfg.ConnConfig.User != "inventory_stock_fixture" {
		t.Fatal("refusing non-fixture authority database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("fixture connection unavailable")
	}
	defer pool.Close()
	var marker string
	if pool.QueryRow(ctx, "SELECT current_setting('stock.fixture_id',true)").Scan(&marker) != nil || marker != run {
		t.Fatal("fixture marker mismatch")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("ephemeral key generation")
	}
	svc, err := service.NewMachineService(postgres.NewMachineRepository(pool), key, "erp-auth", 5*time.Minute)
	if err != nil {
		t.Fatal("service construction")
	}
	ok := func(err error) {
		t.Helper()
		if err != nil {
			var f *domain.MachineFailure
			if errors.As(err, &f) {
				t.Fatalf("authority fixture: reason=%s sqlstate=%s", f.Reason, f.SQLState)
			}
			t.Fatalf("authority fixture error type=%T", err)
		}
	}
	id, err := svc.Create(ctx)
	ok(err)
	credential, err := svc.Rotate(ctx, id, time.Hour)
	ok(err)
	read, _ := domain.ParseMachineAuthority(domain.ReservationAudience, "inventory.reservations:read")
	_, err = svc.IssueFor(ctx, id.String(), credential.Secret, read)
	if !errors.Is(err, domain.ErrMachineClient) {
		t.Fatal("disabled/ungranted machine issued")
	}
	ok(svc.SetEnabled(ctx, id, true))
	ok(svc.SetAuthorityGrant(ctx, id, read, true))
	token, err := svc.IssueFor(ctx, id.String(), credential.Secret, read)
	ok(err)
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("erp-auth"), jwt.WithAudience(domain.ReservationAudience), jwt.WithExpirationRequired())
	ok(err)
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != "machine:"+id.String() || claims["token_kind"] != "machine" || claims["user_id"] != nil || claims["exp"].(float64)-claims["iat"].(float64) != 300 {
		t.Fatal("issued machine separation/lifetime")
	}
	both, _ := domain.ParseMachineAuthority(domain.ReservationAudience, "inventory.reservations:consume inventory.reservations:read")
	_, err = svc.IssueFor(ctx, id.String(), credential.Secret, both)
	if !errors.Is(err, domain.ErrMachineClient) {
		t.Fatal("partial grants broadened scope")
	}
	ok(svc.SetGrant(ctx, id, true))
	_, err = svc.Issue(ctx, id.String(), credential.Secret)
	ok(err)
	ok(svc.SetGrant(ctx, id, false))
	_, err = svc.Issue(ctx, id.String(), credential.Secret)
	if !errors.Is(err, domain.ErrMachineClient) {
		t.Fatal("Catalog grant not revoked")
	}
	_, err = svc.IssueFor(ctx, id.String(), credential.Secret, read)
	ok(err) // Legacy Cat revoke preserves other audience.
	ok(svc.SetAuthorityGrant(ctx, id, read, false))
	_, err = svc.IssueFor(ctx, id.String(), credential.Secret, read)
	if !errors.Is(err, domain.ErrMachineClient) {
		t.Fatal("revoked scope issued")
	}
	if _, err = jwt.Parse(token, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithAudience(domain.ReservationAudience)); err != nil {
		t.Fatal("short-lived signed token unexpectedly depended on grants")
	}
	ok(svc.SetAuthorityGrant(ctx, id, read, true))
	ok(svc.Revoke(ctx, id, credential.ID))
	_, err = svc.IssueFor(ctx, id.String(), credential.Secret, read)
	if !errors.Is(err, domain.ErrMachineClient) {
		t.Fatal("revoked credential issued")
	}
	t.Log("PASS: application lifecycle services + real PostgreSQL; exact scoped grants, requested subset, legacy Catalog revoke isolation, revocation and signed machine identity/lifetime; no normal provisioning")
}
