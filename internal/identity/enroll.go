package identity

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/securefs"
)

// Enroller is the API call enrollment uses.
type Enroller interface {
	Enroll(ctx context.Context, req api.EnrollRequest) (*api.EnrollResponse, error)
}

// EnrollOptions are the inputs to Enroll.
type EnrollOptions struct {
	// Token is the one-time enrollment token from the dashboard.
	Token string
	// Version, OS and Arch describe this connector to KrakenKey.
	Version, OS, Arch string
	// APIURL is recorded in connector.json, so a later change of
	// krakenkey.api_url can be pointed out.
	APIURL string
	// Force enrolls even if an identity exists. The old files are kept
	// with a .bak-<time> suffix.
	Force bool
	Now   time.Time
}

// EnrollResult says what Enroll did.
type EnrollResult struct {
	Identity *Identity
	// Backups are the old identity files kept by a forced enrollment.
	Backups []string
}

// Enroll creates an identity key, registers its public key with KrakenKey
// using the enrollment token, and stores the key and the connector id. The
// caller holds the data directory lock.
//
// The new key is written to disk before KrakenKey is called, so a full or
// read-only disk is found before the single-use token is spent. The old
// identity, if any, stays in place until KrakenKey has accepted the new one.
func (s *Store) Enroll(ctx context.Context, client Enroller, opts EnrollOptions) (*EnrollResult, error) {
	if err := securefs.EnsurePrivateDir(s.dir); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	existing, loadErr := s.Load()
	if !opts.Force {
		if loadErr != nil {
			return nil, loadErr
		}
		if existing != nil {
			return nil, fmt.Errorf("%w as %s; to replace its identity, enroll with --force and a new token", ErrAlreadyEnrolled, existing)
		}
	}

	key, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	if err := s.writeKey(newKeyFile, key); err != nil {
		return nil, err
	}
	resp, err := client.Enroll(ctx, api.EnrollRequest{
		Token:     opts.Token,
		PublicKey: EncodePublicKey(key.Public().(ed25519.PublicKey)),
		Version:   opts.Version,
		OS:        opts.OS,
		Arch:      opts.Arch,
	})
	if err != nil {
		_ = s.removeIfExists(newKeyFile)
		return nil, err
	}

	res := &EnrollResult{}
	stamp := opts.Now.UTC().Format("20060102T150405Z")
	for _, name := range []string{KeyFile, MetaFile, NextKeyFile} {
		ok, err := s.exists(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		backup := s.path(name + ".bak-" + stamp)
		if err := os.Rename(s.path(name), backup); err != nil {
			return nil, fmt.Errorf("identity: keep old %s: %w", name, err)
		}
		res.Backups = append(res.Backups, backup)
	}
	if err := os.Rename(s.path(newKeyFile), s.path(KeyFile)); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	meta := Meta{ConnectorID: resp.ConnectorID, Name: resp.Name, APIURL: opts.APIURL, EnrolledAt: opts.Now.UTC().Truncate(time.Second)}
	if err := s.writeMeta(meta); err != nil {
		return nil, err
	}
	if err := securefs.SyncDir(s.dir); err != nil {
		return nil, err
	}
	res.Identity = &Identity{Meta: meta, key: key}
	return res, nil
}
