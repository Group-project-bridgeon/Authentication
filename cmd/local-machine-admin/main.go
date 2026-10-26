// Local operator utility. No HTTP routes and no credentials in arguments/output.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/group-project/authentication/internal/domain"
	"github.com/group-project/authentication/internal/helper"
	"github.com/group-project/authentication/internal/repository/postgres"
	"github.com/group-project/authentication/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

type lifecycle interface {
	Create(context.Context) (uuid.UUID, error)
	SetGrant(context.Context, uuid.UUID, bool) error
	Rotate(context.Context, uuid.UUID, time.Duration) (domain.MachineCredential, error)
	SetEnabled(context.Context, uuid.UUID, bool) error
}
type serviceFactory func(func(uuid.UUID, uuid.UUID, string) error) (lifecycle, error)

type intentRepository struct {
	domain.MachineRepository
	remember func(uuid.UUID, uuid.UUID, string) error
}

func (r intentRepository) Create(ctx context.Context, id uuid.UUID) error {
	if r.remember(id, uuid.Nil, "create-intent") != nil {
		return failed
	}
	return r.MachineRepository.Create(ctx, id)
}
func (r intentRepository) Rotate(ctx context.Context, id, cid uuid.UUID, hash []byte, age time.Duration) (time.Time, error) {
	if r.remember(id, cid, "rotation-intent") != nil {
		return time.Time{}, failed
	}
	return r.MachineRepository.Rotate(ctx, id, cid, hash, age)
}

type receipt struct {
	Machine    uuid.UUID `json:"machine_id"`
	Credential uuid.UUID `json:"credential_id"`
	Expiry     time.Time `json:"expires_at"`
	Phase      string    `json:"phase"`
}

type stopError struct{ cause error }

func (e stopError) Error() string {
	return "local provisioning stopped; reconcile the journal before retry"
}
func (e stopError) Unwrap() error { return e.cause }

var failed = errors.New("local provisioning stopped; inspect receipt before any retry")

// Reserve both files before mutation. Existing receipts always require operator
// reconciliation; this command never blindly creates a replacement identity.
func provision(ctx context.Context, factory serviceFactory, dir string) (r receipt, err error) {
	if _, e := os.Lstat(filepath.Join(dir, "machine-state.json")); !os.IsNotExist(e) {
		return r, failed
	}
	state, err := os.OpenFile(filepath.Join(dir, "machine-journal.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return r, failed
	}
	defer state.Close()
	credential, err := os.OpenFile(filepath.Join(dir, "inventory-credential.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return r, failed
	}
	defer credential.Close()
	persist := func() error {
		if e := json.NewEncoder(state).Encode(r); e != nil {
			return failed
		}
		if e := state.Sync(); e != nil {
			return failed
		}
		return nil
	}
	r.Phase = "reserved"
	if persist() != nil {
		return r, failed
	}
	s, e := factory(func(id, cid uuid.UUID, phase string) error {
		r.Machine = id
		if cid != uuid.Nil {
			r.Credential = cid
		}
		r.Phase = phase
		return persist()
	})
	if e != nil {
		return r, failed
	}
	r.Machine, err = s.Create(ctx)
	r.Phase = "create-returned"
	if e := persist(); e != nil {
		return r, e
	}
	if err != nil {
		return r, stopError{err}
	}
	r.Phase = "grant-intent"
	if persist() != nil {
		return r, failed
	}
	if e := s.SetGrant(ctx, r.Machine, true); e != nil {
		return r, stopError{e}
	}
	r.Phase = "granted"
	if persist() != nil {
		return r, failed
	}
	c, e := s.Rotate(ctx, r.Machine, 30*24*time.Hour)
	r.Credential, r.Expiry, r.Phase = c.ID, c.ExpiresAt, "rotation-returned"
	if persist() != nil {
		return r, failed
	}
	if e != nil {
		return r, stopError{e}
	}
	parts := strings.SplitN(c.Secret, ".", 2)
	if len(parts) != 2 || parts[0] != c.ID.String() {
		return r, failed
	}
	// Only delivery formatting lives here; randomness/hashing/expiry/rotation are
	// exclusively owned by the existing MachineService and repository.
	if json.NewEncoder(credential).Encode(struct {
		ID     string `json:"credential_id"`
		Secret string `json:"secret"`
	}{c.ID.String(), parts[1]}) != nil || credential.Sync() != nil {
		return r, failed
	}
	r.Phase = "credential-delivered"
	if persist() != nil {
		return r, failed
	}
	r.Phase = "enable-intent"
	if persist() != nil {
		return r, failed
	}
	if e := s.SetEnabled(ctx, r.Machine, true); e != nil {
		return r, stopError{e}
	}
	r.Phase = "enabled"
	if persist() != nil {
		return r, failed
	}
	return r, nil
}
func localHost(host string) bool {
	return host == "postgres" || host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func run() (receipt, error) {
	dir := flag.String("output-dir", "", "existing protected directory")
	ack := flag.String("local-database", "", "explicit local target database")
	host := flag.String("local-host", "", "explicit local target host (postgres or loopback)")
	flag.Parse()
	if *ack == "" || !filepath.IsAbs(*dir) || !localHost(*host) {
		return receipt{}, failed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, e := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if e != nil || cfg.ConnConfig.Database != *ack || cfg.ConnConfig.Host != *host {
		return receipt{}, failed
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if fallback.Host != *host {
			return receipt{}, failed
		}
	}
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return receipt{}, failed
	}
	defer p.Close()
	k, e := helper.LoadRSAPrivateKey(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if e != nil {
		return receipt{}, failed
	}
	return provision(ctx, func(remember func(uuid.UUID, uuid.UUID, string) error) (lifecycle, error) {
		return service.NewMachineService(intentRepository{postgres.NewMachineRepository(p), remember}, k, os.Getenv("JWT_ISSUER"), 5*time.Minute)
	}, *dir)
}
func main() {
	r, e := run()
	if e != nil {
		log := zerolog.New(os.Stderr)
		event := log.Error().Bool("outcome_unknown", errors.Is(e, domain.ErrMachineOutcomeUnknown))
		var dbFailure *domain.MachineFailure
		if errors.As(e, &dbFailure) && len(dbFailure.SQLState) == 5 {
			valid := true
			for _, c := range dbFailure.SQLState {
				if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z') {
					valid = false
				}
			}
			if valid {
				event.Str("sqlstate", dbFailure.SQLState)
			}
		}
		event.Str("component", "local_machine_admin").Str("operation", "provision").Str("reason", "reconciliation_required").Stringer("machine_id", r.Machine).Stringer("credential_id", r.Credential).Msg("Provisioning stopped; inspect protected receipt")
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
