// Command krakenkey-connector renews KrakenKey certificates and deploys
// them to your systems.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/connector"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/identity"
	"github.com/krakenkey/connector/internal/lock"
	"github.com/krakenkey/connector/internal/pluginhost"
	"github.com/krakenkey/connector/internal/procsec"
	"github.com/krakenkey/connector/internal/securefs"
	"github.com/krakenkey/connector/internal/verify"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK        = 0 // every certificate and target succeeded
	exitFailed    = 1 // a certificate or target failed (details in the log)
	exitUsage     = 2 // bad flags, bad config, or no API key
	exitAuth      = 3 // the API rejected the key; the pass stopped
	exitRateLimit = 4 // KrakenKey asked to back off; the pass stopped
	exitIdentity  = 5 // KrakenKey refused the connector's identity; the pass stopped
)

const defaultConfigPath = "/etc/krakenkey-connector/config.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: krakenkey-connector <command> [flags]

Commands:
  enrol            Enrol this connector with a one-time token from the dashboard
  rotate-identity  Replace the connector's identity key
  run              Renew and deploy certificates every check_interval
  run --once       Run a single pass and exit (for cron or systemd timers)
  validate         Check the config, plugins and API access, then exit
  version          Print the version

Run "krakenkey-connector <command> -h" for the flags of a command.

An enrolled connector gets short-lived API keys by proving its identity.
Otherwise the API key is read from the file named by KK_API_KEY_FILE, from
the systemd credential kk_api_key, or from the KK_API_KEY environment
variable. The enrolment token is read the same way from
KK_ENROLMENT_TOKEN_FILE, the credential kk_enrolment_token, or
KK_ENROLMENT_TOKEN.

Exit codes: 0 success, 1 a certificate or target failed, 2 usage or config
error, 3 API key or enrolment token rejected, 4 rate limited, 5 connector
identity rejected (revoked or invalid).
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "enrol", "enroll":
		return cmdEnrol(args[1:], stdout, stderr)
	case "rotate-identity":
		return cmdRotateIdentity(args[1:], stdout, stderr)
	case "run":
		return cmdRun(args[1:], stderr)
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "krakenkey-connector %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

type commonFlags struct {
	configPath string
	logFormat  string
	logLevel   string
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	def := os.Getenv("KK_CONNECTOR_CONFIG")
	if def == "" {
		def = defaultConfigPath
	}
	fs.StringVar(&c.configPath, "config", def, "config file (env KK_CONNECTOR_CONFIG)")
	fs.StringVar(&c.logFormat, "log-format", "text", "log format: text or json")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn or error")
}

func (c *commonFlags) logger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.logLevel)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch c.logFormat {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("--log-format must be text or json, not %q", c.logFormat)
}

// secretSource says where a secret comes from: a file named by an
// environment variable, a systemd credential, or an environment variable.
type secretSource struct {
	what       string // for messages
	env        string // the value itself
	fileEnv    string // a file holding it
	credential string // name in $CREDENTIALS_DIRECTORY
}

var (
	// apiKeySecret: LoadCredential=kk_api_key:/path/to/key.
	apiKeySecret = secretSource{what: "API key", env: "KK_API_KEY", fileEnv: "KK_API_KEY_FILE", credential: "kk_api_key"}
	// enrolmentTokenSecret: LoadCredential=kk_enrolment_token:/path/to/token.
	enrolmentTokenSecret = secretSource{what: "enrolment token", env: "KK_ENROLMENT_TOKEN",
		fileEnv: "KK_ENROLMENT_TOKEN_FILE", credential: "kk_enrolment_token"}
)

// loadAPIKey finds the API key: the file in KK_API_KEY_FILE, then the
// systemd credential, then KK_API_KEY. KK_API_KEY is removed from the
// environment either way, so commands and plugins started later do not
// inherit it. A key file must not be readable by other users.
func loadAPIKey(log *slog.Logger) (key, source string, err error) {
	return loadSecret(log, apiKeySecret)
}

// loadSecret reads a secret from its file, its systemd credential, or its
// environment variable, in that order, and removes the variable from the
// environment either way. A file must not be readable by other users.
func loadSecret(log *slog.Logger, src secretSource) (value, source string, err error) {
	envValue := strings.TrimSpace(os.Getenv(src.env))
	_ = os.Unsetenv(src.env)

	path := os.Getenv(src.fileEnv)
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if p := filepath.Join(dir, src.credential); fileExists(p) {
				path = p
			}
		}
	}
	if path == "" {
		return envValue, src.env, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("%s file: %w", src.what, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return "", "", fmt.Errorf("%s file %s is readable by other users (mode %04o); run: chmod o-rwx %s",
			src.what, path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("%s file: %w", src.what, err)
	}
	if envValue != "" && log != nil {
		log.Warn("both a file and an environment variable are set; using the file", "secret", src.what, "file", path, "ignored", src.env)
	}
	return strings.TrimSpace(string(data)), "file " + path, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func userAgent() string {
	return fmt.Sprintf("krakenkey-connector/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func cmdRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	once := fs.Bool("once", false, "run a single pass and exit")
	force := fs.Bool("force", false, "with --once: renew even if the certificate is not due")
	certID := fs.Int("cert", 0, "with --once: only process this certificate id")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	if (*force || *certID != 0) && !*once {
		fmt.Fprintln(stderr, "--force and --cert need --once")
		return exitUsage
	}

	log, err := common.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if err := procsec.Harden(); err != nil {
		log.Warn("could not make the process non-dumpable", "error", err)
	}
	_ = os.Unsetenv(enrolmentTokenSecret.env)
	apiKey, keySource, err := loadAPIKey(log)
	if err != nil {
		log.Error("cannot read the API key", "error", err)
		return exitUsage
	}
	cfg, err := config.Load(common.configPath)
	if err != nil {
		log.Error("cannot load config", "error", err)
		return exitUsage
	}
	if *certID != 0 {
		if _, ok := cfg.FindCertificate(*certID); !ok {
			log.Error("--cert is not in the config", "certificate_id", *certID)
			return exitUsage
		}
	}
	if err := securefs.EnsurePrivateDir(cfg.DataDir); err != nil {
		log.Error("data dir is not private", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}

	lk, err := lock.Acquire(cfg.DataDir)
	if err != nil {
		log.Error("cannot lock data dir", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}
	defer func() { _ = lk.Release() }()

	store := identity.NewStore(cfg.DataDir)
	ident, err := store.Load()
	if err != nil {
		log.Error("cannot load the connector identity", "error", err)
		return exitFailed
	}
	client, credential, ok := apiClient(log, cfg, store, ident, apiKey, keySource)
	if !ok {
		return exitUsage
	}

	auditLog, err := audit.Open(cfg.AuditLog)
	if err != nil {
		log.Error("cannot open audit log", "error", err)
		return exitFailed
	}
	defer func() { _ = auditLog.Close() }()

	state, err := deploy.OpenStateStore(cfg.DataDir)
	if err != nil {
		log.Error("cannot open state", "error", err)
		return exitFailed
	}

	host := pluginhost.New(cfg, log)
	defer host.Close()

	c := &connector.Connector{
		Config:   cfg,
		Resolver: host,
		Log:      log,
		Engine: &deploy.Engine{
			API:      client,
			Verifier: verify.New(),
			Audit:    auditLog,
			State:    state,
			Log:      log,
		},
	}
	if ident != nil {
		c.Reporter = &connector.Reporter{
			API: client, State: state, Config: cfg, Log: log,
			Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("krakenkey-connector starting", "version", version, "api_url", cfg.KrakenKey.APIURL,
		"config", common.configPath, "once", *once, "credential", credential)

	if *once {
		err = c.RunOnce(ctx, connector.RunOptions{Force: *force, CertID: *certID})
	} else {
		err = c.Run(ctx)
	}
	return exitCode(log, err)
}

// exitCode maps the result of a pass, or of run mode, to an exit code.
func exitCode(log *slog.Logger, err error) int {
	var authErr *api.AuthError
	var connAuthErr *api.ConnectorAuthError
	var rl *api.RateLimitError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &connAuthErr):
		log.Error("stopping: KrakenKey refused the connector's identity", "error", connAuthErr)
		return exitIdentity
	case errors.As(err, &authErr):
		log.Error("stopping: the API key was rejected", "error", authErr)
		return exitAuth
	case errors.As(err, &rl):
		log.Error("stopping: KrakenKey asked the connector to back off", "retry_after", rl.RetryAfter)
		return exitRateLimit
	}
	log.Error("finished with errors", "error", err)
	return exitFailed
}

// apiClient picks the credential for API calls: the connector identity if
// the connector is enrolled, otherwise the API key. ok is false (and the
// reason logged) when there is neither.
func apiClient(log *slog.Logger, cfg *config.Config, store *identity.Store, ident *identity.Identity,
	apiKey, keySource string,
) (client *api.Client, credential string, ok bool) {
	if ident == nil {
		if apiKey == "" {
			log.Error("no credentials: the connector is not enrolled (run enrol) and no API key is set " +
				"(KK_API_KEY_FILE, the kk_api_key systemd credential, or KK_API_KEY)")
			return nil, "", false
		}
		log.Info("the connector is not enrolled; using the API key", "api_key_from", keySource)
		return api.NewClient(cfg.KrakenKey.APIURL, apiKey, userAgent()), "API key from " + keySource, true
	}
	if apiKey != "" {
		log.Warn("the connector is enrolled; the API key is ignored", "api_key_from", keySource)
	}
	if ident.APIURL != "" && ident.APIURL != cfg.KrakenKey.APIURL {
		log.Warn("the connector was enrolled with a different API URL", "enrolled_with", ident.APIURL, "api_url", cfg.KrakenKey.APIURL)
	}
	client, _ = identityClient(log, cfg, store, ident, false)
	return client, "connector identity " + ident.ConnectorID, true
}

// identityClient returns a client whose bearer tokens are short-lived keys
// from a token source for ident. The same client makes the (unauthenticated)
// token exchanges.
func identityClient(log *slog.Logger, cfg *config.Config, store *identity.Store, ident *identity.Identity,
	readOnly bool,
) (*api.Client, *identity.TokenSource) {
	var tokens *identity.TokenSource
	client := api.NewClientWithKeys(cfg.KrakenKey.APIURL, api.KeySourceFunc(func(ctx context.Context) (string, error) {
		return tokens.APIKey(ctx)
	}), userAgent())
	tokens = identity.NewTokenSource(client, store, ident, log)
	tokens.ReadOnly = readOnly
	return client, tokens
}

func cmdEnrol(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	force := fs.Bool("force", false, "enrol again although an identity exists; the old identity files are kept as backups")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	log, err := common.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if err := procsec.Harden(); err != nil {
		log.Warn("could not make the process non-dumpable", "error", err)
	}
	token, _, err := loadSecret(log, enrolmentTokenSecret)
	if err != nil {
		log.Error("cannot read the enrolment token", "error", err)
		return exitUsage
	}
	if token == "" {
		log.Error("no enrolment token: set KK_ENROLMENT_TOKEN_FILE, the kk_enrolment_token systemd credential, or KK_ENROLMENT_TOKEN")
		return exitUsage
	}
	if !strings.HasPrefix(token, "kkce_") {
		log.Error("that is not an enrolment token: enrolment tokens start with kkce_ (create one for this connector in the dashboard)")
		return exitUsage
	}
	cfg, err := config.Load(common.configPath)
	if err != nil {
		log.Error("cannot load config", "error", err)
		return exitUsage
	}
	if err := securefs.EnsurePrivateDir(cfg.DataDir); err != nil {
		log.Error("data dir is not private", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}
	lk, err := lock.Acquire(cfg.DataDir)
	if err != nil {
		log.Error("cannot lock data dir", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}
	defer func() { _ = lk.Release() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := api.NewClient(cfg.KrakenKey.APIURL, "", userAgent())
	res, err := identity.NewStore(cfg.DataDir).Enrol(ctx, client, identity.EnrolOptions{
		Token: token, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		APIURL: cfg.KrakenKey.APIURL, Force: *force, Now: time.Now(),
	})
	var tokErr *api.EnrolmentTokenError
	var rl *api.RateLimitError
	switch {
	case errors.Is(err, identity.ErrAlreadyEnrolled):
		log.Error("not enrolling", "error", err)
		return exitUsage
	case errors.As(err, &tokErr):
		log.Error("enrolment failed", "error", tokErr)
		return exitAuth
	case errors.As(err, &rl):
		log.Error("enrolment failed: KrakenKey asked the connector to back off", "retry_after", rl.RetryAfter)
		return exitRateLimit
	case err != nil:
		log.Error("enrolment failed", "error", err)
		return exitFailed
	}
	for _, b := range res.Backups {
		fmt.Fprintf(stdout, "Kept the previous identity file as %s\n", b)
	}
	fmt.Fprintf(stdout, "Enrolled as connector %q (id %s).\n", res.Identity.Name, res.Identity.ConnectorID)
	return exitOK
}

func cmdRotateIdentity(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rotate-identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return exitUsage
	}
	log, err := common.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if err := procsec.Harden(); err != nil {
		log.Warn("could not make the process non-dumpable", "error", err)
	}
	cfg, err := config.Load(common.configPath)
	if err != nil {
		log.Error("cannot load config", "error", err)
		return exitUsage
	}
	if err := securefs.CheckPrivate(cfg.DataDir); err != nil {
		log.Error("data dir is not usable", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}
	lk, err := lock.Acquire(cfg.DataDir)
	if err != nil {
		log.Error("cannot lock data dir", "data_dir", cfg.DataDir, "error", err)
		return exitFailed
	}
	defer func() { _ = lk.Release() }()

	store := identity.NewStore(cfg.DataDir)
	ident, err := store.Load()
	if err != nil {
		log.Error("cannot load the connector identity", "error", err)
		return exitFailed
	}
	if ident == nil {
		log.Error("the connector is not enrolled; run enrol first")
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := api.NewClient(cfg.KrakenKey.APIURL, "", userAgent())
	// A token exchange first: it checks that the current key works and
	// settles a rotation an earlier run left unfinished.
	if _, err := identity.NewTokenSource(client, store, ident, log).APIKey(ctx); err != nil {
		return exitCode(log, err)
	}
	if err := store.Rotate(ctx, client, ident, time.Now()); err != nil {
		return exitCode(log, fmt.Errorf("rotate identity: %w", err))
	}
	log.Info("identity key rotated", "connector_id", ident.ConnectorID)
	fmt.Fprintf(stdout, "Rotated the identity key of connector %q (id %s).\n", ident.Name, ident.ConnectorID)
	return exitOK
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	offline := fs.Bool("offline", false, "skip the KrakenKey API checks")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	log, err := common.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if err := procsec.Harden(); err != nil {
		log.Warn("could not make the process non-dumpable", "error", err)
	}
	_ = os.Unsetenv(enrolmentTokenSecret.env)
	apiKey, keySource, keyErr := loadAPIKey(log)
	cfg, err := config.Load(common.configPath)
	if err != nil {
		fmt.Fprintf(stdout, "Config %s: INVALID\n%v\n", common.configPath, err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "Config:     %s\n", common.configPath)
	extra := 0
	if err := securefs.CheckPrivate(cfg.DataDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stdout, "Data dir:   PROBLEM: %v\n", err)
		extra++
	}

	host := pluginhost.New(cfg, log)
	defer host.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var client connector.CertGetter
	store := identity.NewStore(cfg.DataDir)
	ident, identErr := store.Load()
	switch {
	case identErr != nil:
		fmt.Fprintf(stdout, "Identity:   PROBLEM: %v\n", identErr)
		extra++
	case ident == nil:
		fmt.Fprintln(stdout, "Identity:   not enrolled; the API key is used")
	default:
		fmt.Fprintf(stdout, "Identity:   enrolled as connector %q (id %s)\n", ident.Name, ident.ConnectorID)
		if ident.APIURL != "" && ident.APIURL != cfg.KrakenKey.APIURL {
			fmt.Fprintf(stdout, "WARNING: the connector was enrolled with %s, but the config uses %s\n", ident.APIURL, cfg.KrakenKey.APIURL)
		}
	}

	switch {
	case ident != nil:
		if keyErr == nil && apiKey != "" {
			fmt.Fprintf(stdout, "API key:    ignored, the connector is enrolled (%s is set)\n", keySource)
		}
		if *offline {
			fmt.Fprintln(stdout, "Token:      not checked (--offline)")
			break
		}
		c, tokens := identityClient(log, cfg, store, ident, true)
		if _, err := tokens.APIKey(ctx); err != nil {
			fmt.Fprintf(stdout, "Token:      PROBLEM: token exchange failed: %v\n", err)
			extra++
			break
		}
		fmt.Fprintf(stdout, "Token:      exchange works (short-lived key valid until %s)\n", tokens.ExpiresAt().UTC().Format(time.RFC3339))
		client = c
	case keyErr != nil:
		fmt.Fprintf(stdout, "API key:    PROBLEM: %v\n", keyErr)
		extra++
	case *offline:
		fmt.Fprintln(stdout, "API key:    not checked (--offline)")
	case apiKey == "":
		fmt.Fprintln(stdout, "API key:    PROBLEM: not set (KK_API_KEY_FILE, kk_api_key credential, or KK_API_KEY), and the connector is not enrolled")
		extra++
	default:
		fmt.Fprintf(stdout, "API key:    set (%s)\n", keySource)
		client = api.NewClient(cfg.KrakenKey.APIURL, apiKey, userAgent())
	}
	if connector.Validate(ctx, cfg, host, client, stdout)+extra > 0 {
		return exitFailed
	}
	return exitOK
}
