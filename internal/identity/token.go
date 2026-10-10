package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/krakenkey/connector/internal/api"
)

// Exchanger is the API call the token source uses.
type Exchanger interface {
	ConnectorToken(ctx context.Context, req api.ConnectorTokenRequest) (*api.ConnectorToken, error)
}

// RefreshBefore is how long before a short-lived key expires the token
// source gets a new one.
const RefreshBefore = 5 * time.Minute

// minCache is the shortest time a key is reused when its expiry is already
// within RefreshBefore (a clock far off from KrakenKey's).
const minCache = time.Minute

// TokenSource is an api.KeySource that gets short-lived API keys by
// signing a request with the identity key. A key is kept in memory until
// RefreshBefore its expiry and never written to disk.
//
// A 401 from KrakenKey (revoked connector, unknown key, clock too far off)
// is remembered: every later call returns the same *api.ConnectorAuthError
// without contacting KrakenKey again.
//
// If an earlier rotation did not finish, the first exchange works out
// which key KrakenKey has: the current key is tried first, then the
// rotation key. Unless ReadOnly is set, the key that works is kept and the
// other one removed.
type TokenSource struct {
	API   Exchanger
	Store *Store
	Log   *slog.Logger
	// ReadOnly leaves the identity files alone (for validate, which does
	// not hold the data directory lock).
	ReadOnly bool
	// Now defaults to time.Now.
	Now func() time.Time

	mu        sync.Mutex
	id        *Identity
	key       string
	expiresAt time.Time
	refreshAt time.Time
	failed    error
}

// NewTokenSource returns a token source for id.
func NewTokenSource(client Exchanger, store *Store, id *Identity, log *slog.Logger) *TokenSource {
	return &TokenSource{API: client, Store: store, Log: log, id: id}
}

func (s *TokenSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// APIKey returns a short-lived API key, from memory while it is fresh.
func (s *TokenSource) APIKey(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return "", s.failed
	}
	now := s.now()
	if s.key != "" && now.Before(s.refreshAt) {
		return s.key, nil
	}

	tok, err := s.exchange(ctx, s.id.key)
	var authErr *api.ConnectorAuthError
	switch {
	case err == nil && s.id.next != nil:
		s.resolveRotation(false)
	case errors.As(err, &authErr) && s.id.next != nil:
		var nextErr error
		tok, nextErr = s.exchange(ctx, s.id.next)
		if nextErr == nil {
			s.resolveRotation(true)
			err = nil
		} else if !errors.As(nextErr, new(*api.ConnectorAuthError)) {
			err = nextErr
		}
	}
	if errors.As(err, &authErr) {
		s.failed = authErr
		s.key = ""
		return "", authErr
	}
	if err != nil {
		return "", err
	}

	s.key, s.expiresAt = tok.APIKey, tok.ExpiresAt
	s.refreshAt = tok.ExpiresAt.Add(-RefreshBefore)
	if !s.refreshAt.After(now) {
		s.Log.Warn("the short-lived API key expires within minutes by this machine's clock; check the clock",
			"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339))
		s.refreshAt = now.Add(minCache)
	}
	s.Log.Debug("got a short-lived API key", "connector_id", s.id.ConnectorID,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339))
	return s.key, nil
}

// ExpiresAt returns the expiry of the key in memory, or zero.
func (s *TokenSource) ExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}

func (s *TokenSource) exchange(ctx context.Context, key ed25519.PrivateKey) (*api.ConnectorToken, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	ts := Timestamp(s.now())
	return s.API.ConnectorToken(ctx, api.ConnectorTokenRequest{
		ConnectorID: s.id.ConnectorID,
		Timestamp:   ts,
		Nonce:       nonce,
		Signature:   sign(key, TokenMessage(s.id.ConnectorID, ts, nonce)),
	})
}

// resolveRotation settles an unfinished rotation: nextWorks says whether
// KrakenKey accepted the rotation key.
func (s *TokenSource) resolveRotation(nextWorks bool) {
	if nextWorks {
		s.id.key, s.id.next = s.id.next, nil
		if s.ReadOnly {
			s.Log.Warn("an identity rotation finished on KrakenKey's side but not here; the next run or rotate-identity completes it")
			return
		}
		if err := s.Store.promoteNext(); err != nil {
			s.Log.Error("KrakenKey has the new identity key, but it could not be made current here", "error", err)
			return
		}
		s.Log.Info("finished an interrupted identity rotation; KrakenKey has the new key")
		return
	}
	s.id.next = nil
	if s.ReadOnly {
		s.Log.Warn("an identity rotation did not reach KrakenKey; the next run or rotate-identity cleans it up")
		return
	}
	if err := s.Store.removeIfExists(NextKeyFile); err != nil {
		s.Log.Warn("could not remove the key of an unfinished rotation", "error", err)
		return
	}
	s.Log.Info("removed the key of an identity rotation that did not reach KrakenKey; the current key is still valid")
}
