package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/fakekk"
)

const enrollToken = "kkce_test_token_0123456789abcdef"

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newClient(srv *fakekk.Server) *api.Client {
	return api.NewClient(srv.URL, "", "krakenkey-connector/test")
}

func enroll(t *testing.T, srv *fakekk.Server, dataDir string) (*Store, *Identity) {
	t.Helper()
	srv.AddEnrollmentToken(enrollToken, "edge-1")
	store := NewStore(dataDir)
	res, err := store.Enroll(context.Background(), newClient(srv), EnrollOptions{
		Token: enrollToken, Version: "test", OS: "linux", Arch: "amd64", APIURL: srv.URL, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return store, res.Identity
}

func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s has mode %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func TestEnrollStoresIdentity(t *testing.T) {
	srv := fakekk.New(t)
	dataDir := t.TempDir()
	store, id := enroll(t, srv, dataDir)

	if id.Name != "edge-1" || id.ConnectorID == "" {
		t.Errorf("identity %+v", id.Meta)
	}
	c := srv.Connector(id.ConnectorID)
	if c == nil || c.Version != "test" || c.OS != "linux" || c.Arch != "amd64" {
		t.Fatalf("connector on the server: %+v", c)
	}
	if !c.PublicKey.Equal(id.key.Public()) {
		t.Error("the server holds a different public key")
	}

	checkMode(t, store.Dir(), 0o700)
	checkMode(t, filepath.Join(store.Dir(), KeyFile), 0o600)
	checkMode(t, filepath.Join(store.Dir(), MetaFile), 0o600)
	entries, _ := os.ReadDir(store.Dir())
	if len(entries) != 2 {
		t.Errorf("identity dir holds %d files, want 2: %v", len(entries), entries)
	}

	loaded, err := store.Load()
	if err != nil || loaded == nil {
		t.Fatalf("Load: %v %v", loaded, err)
	}
	if loaded.ConnectorID != id.ConnectorID || loaded.APIURL != srv.URL || !loaded.key.Equal(id.key) {
		t.Errorf("loaded %+v", loaded.Meta)
	}
}

func TestEnrollRefusesToReenroll(t *testing.T) {
	srv := fakekk.New(t)
	dataDir := t.TempDir()
	store, first := enroll(t, srv, dataDir)

	srv.AddEnrollmentToken("kkce_second_token_0123456789", "edge-2")
	_, err := store.Enroll(context.Background(), newClient(srv), EnrollOptions{Token: "kkce_second_token_0123456789", Now: time.Now(), Version: "v", OS: "o", Arch: "a"})
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second enroll: %v", err)
	}
	if n := len(srv.Requests()); n != 1 {
		t.Errorf("refusing to re-enroll still called KrakenKey (%d requests)", n)
	}

	// A forced enrollment with a bad token keeps the existing identity.
	_, err = store.Enroll(context.Background(), newClient(srv), EnrollOptions{Token: "kkce_wrong_token_0123456789", Force: true, Now: time.Now(), Version: "v", OS: "o", Arch: "a"})
	var tokErr *api.EnrollmentTokenError
	if !errors.As(err, &tokErr) {
		t.Fatalf("bad token: %v", err)
	}
	if strings.Contains(err.Error(), "kkce_wrong") {
		t.Error("the token is in the error")
	}
	if got, _ := store.Load(); got == nil || got.ConnectorID != first.ConnectorID {
		t.Fatalf("failed forced enrollment changed the identity: %v", got)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), newKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("the key of the failed enrollment was left behind")
	}

	// A forced enrollment that works keeps the old files as backups.
	res, err := store.Enroll(context.Background(), newClient(srv), EnrollOptions{Token: "kkce_second_token_0123456789", Force: true, Now: time.Now(), Version: "v", OS: "o", Arch: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Identity.ConnectorID == first.ConnectorID || len(res.Backups) != 2 {
		t.Fatalf("forced enroll: %+v", res)
	}
	for _, b := range res.Backups {
		checkMode(t, b, 0o600)
	}
	oldKey, err := store.readKey(filepath.Base(res.Backups[0]))
	if err != nil || !oldKey.Equal(first.key) {
		t.Errorf("backup %s does not hold the old key: %v", res.Backups[0], err)
	}
	if got, _ := store.Load(); got.ConnectorID != res.Identity.ConnectorID {
		t.Errorf("loaded %s after forced enroll", got)
	}
}

func TestLoadChecksPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix permissions")
	}
	srv := fakekk.New(t)
	store, _ := enroll(t, srv, t.TempDir())
	keyPath := filepath.Join(store.Dir(), KeyFile)
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("group-readable key loaded: %v", err)
	}
	_ = os.Chmod(keyPath, 0o600)
	_ = os.Chmod(store.Dir(), 0o750)
	if _, err := store.Load(); err == nil {
		t.Error("group-readable identity dir accepted")
	}
	_ = os.Chmod(store.Dir(), 0o700)

	// Half an identity is an error, not "not enrolled".
	_ = os.Remove(filepath.Join(store.Dir(), MetaFile))
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("key without connector.json: %v", err)
	}
}

func TestLoadNotEnrolled(t *testing.T) {
	id, err := NewStore(filepath.Join(t.TempDir(), "missing")).Load()
	if id != nil || err != nil {
		t.Errorf("Load = %v, %v", id, err)
	}
}

func TestIdentityNeverPrintsKeys(t *testing.T) {
	srv := fakekk.New(t)
	_, id := enroll(t, srv, t.TempDir())
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", "identity", id)
	out := buf.String() + fmt.Sprintf("%v %+v %#v %s", id, id, id, id)
	seedHex := fmt.Sprintf("%x", id.key.Seed())
	seedB64 := base64.StdEncoding.EncodeToString(id.key.Seed())
	for _, leak := range []string{seedHex[:16], seedB64[:16], "PRIVATE KEY"} {
		if strings.Contains(out, leak) {
			t.Errorf("key material printed: %s", out)
		}
	}
	if !strings.Contains(out, id.ConnectorID) {
		t.Errorf("connector id missing: %s", out)
	}
}

func TestMessages(t *testing.T) {
	if got := string(TokenMessage("c1", "2026-10-10T14:00:00Z", "abc")); got != "KRAKENKEY-CONNECTOR-TOKEN-V1\nc1\n2026-10-10T14:00:00Z\nabc" {
		t.Errorf("token message %q", got)
	}
	if got := string(RotateMessage("c1", "PUB=", "2026-10-10T14:00:00Z", "abc")); got != "KRAKENKEY-CONNECTOR-ROTATE-V1\nc1\nPUB=\n2026-10-10T14:00:00Z\nabc" {
		t.Errorf("rotate message %q", got)
	}
	loc := time.FixedZone("x", 5*3600)
	if got := Timestamp(time.Date(2026, 10, 10, 19, 0, 0, 999_999_999, loc)); got != "2026-10-10T14:00:00Z" {
		t.Errorf("timestamp %q", got)
	}
	seen := map[string]bool{}
	for range 100 {
		n, err := NewNonce()
		if err != nil || len(n) != 43 || strings.ContainsAny(n, "+/=") || seen[n] {
			t.Fatalf("nonce %q %v", n, err)
		}
		seen[n] = true
	}
}

// fixedClock is a settable clock shared by the fake server and the token
// source.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestTokenSourceCachesAndRefreshes(t *testing.T) {
	srv := fakekk.New(t)
	clock := &fixedClock{t: time.Now().UTC().Truncate(time.Second)}
	srv.Now = clock.Now
	store, id := enroll(t, srv, t.TempDir())
	ts := NewTokenSource(newClient(srv), store, id, quietLog())
	ts.Now = clock.Now
	ctx := context.Background()

	k1, err := ts.APIKey(ctx)
	if err != nil || !strings.HasPrefix(k1, "kk_") {
		t.Fatalf("APIKey: %q %v", k1, err)
	}
	if !ts.ExpiresAt().Equal(clock.Now().Add(time.Hour)) {
		t.Errorf("expiresAt %v", ts.ExpiresAt())
	}
	clock.Add(54 * time.Minute)
	if k, _ := ts.APIKey(ctx); k != k1 || srv.TokenCalls() != 1 {
		t.Errorf("key not cached: %d exchanges", srv.TokenCalls())
	}
	clock.Add(time.Minute + time.Second) // within 5 minutes of expiry
	k2, err := ts.APIKey(ctx)
	if err != nil || k2 == k1 || srv.TokenCalls() != 2 {
		t.Errorf("key not refreshed 5 minutes before expiry: %d exchanges, err %v", srv.TokenCalls(), err)
	}

	// The key is never written to disk.
	err = filepath.Walk(filepath.Dir(store.Dir()), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, _ := os.ReadFile(p)
		if bytes.Contains(data, []byte(k1)) || bytes.Contains(data, []byte(k2)) {
			t.Errorf("short-lived key written to %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTokenSourceClockSkew(t *testing.T) {
	srv := fakekk.New(t)
	serverNow := time.Now()
	srv.Now = func() time.Time { return serverNow }
	srv.TokenTTL = 4 * time.Minute // expires within RefreshBefore
	store, id := enroll(t, srv, t.TempDir())
	ts := NewTokenSource(newClient(srv), store, id, quietLog())
	for range 3 {
		if _, err := ts.APIKey(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if srv.TokenCalls() != 1 {
		t.Errorf("a key that expires soon was fetched %d times in a row", srv.TokenCalls())
	}
}

func TestTokenSource401IsFinal(t *testing.T) {
	srv := fakekk.New(t)
	store, id := enroll(t, srv, t.TempDir())
	srv.Revoke(id.ConnectorID)
	ts := NewTokenSource(newClient(srv), store, id, quietLog())
	for range 3 {
		_, err := ts.APIKey(context.Background())
		var authErr *api.ConnectorAuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("revoked connector: %v", err)
		}
	}
	if n := srv.TokenCalls(); n != 1 {
		t.Errorf("%d token requests after a 401, want 1", n)
	}
}

func TestTokenSourceRejectedClock(t *testing.T) {
	srv := fakekk.New(t)
	store, id := enroll(t, srv, t.TempDir())
	ts := NewTokenSource(newClient(srv), store, id, quietLog())
	ts.Now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	_, err := ts.APIKey(context.Background())
	if !errors.As(err, new(*api.ConnectorAuthError)) || !strings.Contains(err.Error(), "clock") {
		t.Errorf("skewed clock: %v", err)
	}
}

func TestRotate(t *testing.T) {
	srv := fakekk.New(t)
	store, id := enroll(t, srv, t.TempDir())
	oldKey := id.key
	if err := store.Rotate(context.Background(), newClient(srv), id, time.Now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if id.key.Equal(oldKey) {
		t.Fatal("key not replaced in memory")
	}
	if !srv.Connector(id.ConnectorID).PublicKey.Equal(id.key.Public()) {
		t.Error("the server does not hold the new key")
	}
	loaded, err := store.Load()
	if err != nil || !loaded.key.Equal(id.key) || loaded.RotationPending() {
		t.Fatalf("after rotation: %v, pending %v", err, loaded.RotationPending())
	}
	checkMode(t, filepath.Join(store.Dir(), KeyFile), 0o600)

	// The new key gets tokens; the old one no longer does.
	if _, err := NewTokenSource(newClient(srv), store, loaded, quietLog()).APIKey(context.Background()); err != nil {
		t.Errorf("new key: %v", err)
	}
	old := &Identity{Meta: id.Meta, key: oldKey}
	if _, err := NewTokenSource(newClient(srv), store, old, quietLog()).APIKey(context.Background()); !errors.As(err, new(*api.ConnectorAuthError)) {
		t.Errorf("old key still accepted: %v", err)
	}
}

func TestRotateRefused(t *testing.T) {
	srv := fakekk.New(t)
	store, id := enroll(t, srv, t.TempDir())
	oldKey := id.key
	srv.RotateStatus = 401
	err := store.Rotate(context.Background(), newClient(srv), id, time.Now())
	if !errors.As(err, new(*api.ConnectorAuthError)) {
		t.Fatalf("refused rotation: %v", err)
	}
	loaded, _ := store.Load()
	if !loaded.key.Equal(oldKey) || loaded.RotationPending() {
		t.Error("a refused rotation changed the identity files")
	}
}

// lostAnswer forwards the rotation to KrakenKey (or not) and then reports
// a network error, like a crash or a dropped connection after sending.
type lostAnswer struct {
	client  *api.Client
	deliver bool
}

func (l lostAnswer) RotateIdentity(ctx context.Context, req api.RotateRequest) error {
	if l.deliver {
		if err := l.client.RotateIdentity(ctx, req); err != nil {
			return err
		}
	}
	return errors.New("connection reset")
}

func TestRotationCrashSafety(t *testing.T) {
	for _, delivered := range []bool{true, false} {
		t.Run(fmt.Sprintf("delivered=%v", delivered), func(t *testing.T) {
			srv := fakekk.New(t)
			store, id := enroll(t, srv, t.TempDir())
			oldKey := id.key
			err := store.Rotate(context.Background(), lostAnswer{newClient(srv), delivered}, id, time.Now())
			if !errors.Is(err, ErrRotationUnknown) {
				t.Fatalf("Rotate: %v", err)
			}

			// What a restarted connector finds: both keys, old one current.
			loaded, err := store.Load()
			if err != nil || !loaded.key.Equal(oldKey) || !loaded.RotationPending() {
				t.Fatalf("after an interrupted rotation: %v pending=%v", err, loaded.RotationPending())
			}
			newKey := loaded.next
			checkMode(t, filepath.Join(store.Dir(), NextKeyFile), 0o600)

			// validate (read-only) gets a token but changes nothing.
			ro := NewTokenSource(newClient(srv), store, loaded, quietLog())
			ro.ReadOnly = true
			if _, err := ro.APIKey(context.Background()); err != nil {
				t.Fatalf("read-only exchange: %v", err)
			}
			if again, _ := store.Load(); !again.RotationPending() {
				t.Fatal("read-only token source changed the files")
			}

			// The next run settles it.
			loaded, _ = store.Load()
			if _, err := NewTokenSource(newClient(srv), store, loaded, quietLog()).APIKey(context.Background()); err != nil {
				t.Fatalf("exchange after the interrupted rotation: %v", err)
			}
			final, _ := store.Load()
			want := oldKey
			if delivered {
				want = newKey
			}
			if final.RotationPending() || !final.key.Equal(want) {
				t.Errorf("settled on the wrong key (pending %v)", final.RotationPending())
			}
			if !srv.Connector(id.ConnectorID).PublicKey.Equal(want.Public().(ed25519.PublicKey)) {
				t.Error("server and connector disagree")
			}
		})
	}
}
