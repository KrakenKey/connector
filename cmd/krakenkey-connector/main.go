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

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/connector"
	"github.com/krakenkey/connector/internal/deploy"
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
)

const defaultConfigPath = "/etc/krakenkey-connector/config.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: krakenkey-connector <command> [flags]

Commands:
  run        Renew and deploy certificates every check_interval
  run --once Run a single pass and exit (for cron or systemd timers)
  validate   Check the config, plugins and API access, then exit
  version    Print the version

Run "krakenkey-connector <command> -h" for the flags of a command.

The API key is read from the file named by KK_API_KEY_FILE, from the
systemd credential kk_api_key, or from the KK_API_KEY environment variable.

Exit codes: 0 success, 1 a certificate or target failed, 2 usage or config
error, 3 API key rejected, 4 rate limited.
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
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

// apiKeyCredential is the systemd credential name read from
// $CREDENTIALS_DIRECTORY (LoadCredential=kk_api_key:/path/to/key).
const apiKeyCredential = "kk_api_key"

// loadAPIKey finds the API key: the file in KK_API_KEY_FILE, then the
// systemd credential, then KK_API_KEY. KK_API_KEY is removed from the
// environment either way, so commands and plugins started later do not
// inherit it. A key file must not be readable by other users.
func loadAPIKey(log *slog.Logger) (key, source string, err error) {
	envKey := strings.TrimSpace(os.Getenv("KK_API_KEY"))
	_ = os.Unsetenv("KK_API_KEY")

	path := os.Getenv("KK_API_KEY_FILE")
	if path == "" {
		if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
			if p := filepath.Join(dir, apiKeyCredential); fileExists(p) {
				path = p
			}
		}
	}
	if path == "" {
		return envKey, "KK_API_KEY", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("API key file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o007 != 0 {
		return "", "", fmt.Errorf("API key file %s is readable by other users (mode %04o); run: chmod o-rwx %s",
			path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("API key file: %w", err)
	}
	if envKey != "" && log != nil {
		log.Warn("both an API key file and KK_API_KEY are set; using the file", "file", path)
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
	if apiKey == "" {
		log.Error("no API key: set KK_API_KEY_FILE, the kk_api_key systemd credential, or KK_API_KEY")
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

	client := api.NewClient(cfg.KrakenKey.APIURL, apiKey, userAgent())
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("krakenkey-connector starting", "version", version, "api_url", cfg.KrakenKey.APIURL,
		"config", common.configPath, "once", *once, "api_key_from", keySource)

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
	var rl *api.RateLimitError
	switch {
	case err == nil:
		return exitOK
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

	var client connector.CertGetter
	switch {
	case keyErr != nil:
		fmt.Fprintf(stdout, "API key:    PROBLEM: %v\n", keyErr)
		extra++
	case *offline:
		fmt.Fprintln(stdout, "API key:    not checked (--offline)")
	case apiKey == "":
		fmt.Fprintln(stdout, "API key:    PROBLEM: not set (KK_API_KEY_FILE, kk_api_key credential, or KK_API_KEY)")
		extra++
	default:
		fmt.Fprintf(stdout, "API key:    set (%s)\n", keySource)
		client = api.NewClient(cfg.KrakenKey.APIURL, apiKey, userAgent())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if connector.Validate(ctx, cfg, host, client, stdout)+extra > 0 {
		return exitFailed
	}
	return exitOK
}
