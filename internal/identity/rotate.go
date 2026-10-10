package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/krakenkey/connector/internal/api"
)

// Rotator is the API call rotation uses.
type Rotator interface {
	RotateIdentity(ctx context.Context, req api.RotateRequest) error
}

// ErrRotationUnknown wraps errors after which the connector cannot tell
// whether KrakenKey accepted the new key. Both keys are kept; the next
// token exchange finds out which one KrakenKey has.
var ErrRotationUnknown = errors.New("the outcome of the rotation is unknown; both keys are kept and the next run settles it")

// Rotate replaces the identity key. The caller holds the data directory
// lock and has settled any earlier unfinished rotation (a TokenSource
// exchange does that).
//
// The new key is written to identity.key.next before KrakenKey is asked,
// and renamed over identity.key only after KrakenKey answers 204. A crash
// in between leaves both keys on disk, and the next token exchange keeps
// whichever KrakenKey accepts. When KrakenKey clearly refuses the rotation
// the new key is removed.
func (s *Store) Rotate(ctx context.Context, client Rotator, id *Identity, now time.Time) error {
	if id.next != nil {
		return errors.New("an earlier rotation has not been settled yet")
	}
	key, err := generateKey()
	if err != nil {
		return fmt.Errorf("identity: generate key: %w", err)
	}
	if err := s.writeKey(NextKeyFile, key); err != nil {
		return err
	}
	nonce, err := NewNonce()
	if err != nil {
		_ = s.removeIfExists(NextKeyFile)
		return err
	}
	newPub := EncodePublicKey(key.Public().(ed25519.PublicKey))
	ts := Timestamp(now)
	err = client.RotateIdentity(ctx, api.RotateRequest{
		ConnectorID:  id.ConnectorID,
		NewPublicKey: newPub,
		Timestamp:    ts,
		Nonce:        nonce,
		Signature:    sign(id.key, RotateMessage(id.ConnectorID, newPub, ts, nonce)),
	})
	var rl *api.RateLimitError
	switch {
	case err == nil:
	case api.IsClientError(err), errors.As(err, &rl):
		// KrakenKey answered and did not rotate.
		if rmErr := s.removeIfExists(NextKeyFile); rmErr != nil {
			return errors.Join(err, rmErr)
		}
		return err
	default:
		id.next = key
		return fmt.Errorf("%w: %w", ErrRotationUnknown, err)
	}

	if err := s.promoteNext(); err != nil {
		id.next = key
		return fmt.Errorf("KrakenKey accepted the new key, but it could not be made current here (the next run retries): %w", err)
	}
	id.key = key
	return nil
}
