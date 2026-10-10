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
	"github.com/krakenkey/connector/internal/verify"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
	exitAuth   = 3
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

The API key is read from the KK_API_KEY environment variable.
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

// takeAPIKey reads KK_API_KEY and removes it from the environment, so no
// plugin or command started later inherits it.
func takeAPIKey() string {
	key := strings.TrimSpace(os.Getenv("KK_API_KEY"))
	_ = os.Unsetenv("KK_API_KEY")
	return key
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
	apiKey := takeAPIKey()
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
		log.Error("KK_API_KEY is not set")
		return exitUsage
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
		"config", common.configPath, "once", *once)

	if *once {
		err = c.RunOnce(ctx, connector.RunOptions{Force: *force, CertID: *certID})
	} else {
		err = c.Run(ctx)
	}
	var authErr *api.AuthError
	switch {
	case errors.As(err, &authErr):
		log.Error("stopping: the API key was rejected", "error", authErr)
		return exitAuth
	case err != nil:
		return exitFailed
	}
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
	apiKey := takeAPIKey()
	cfg, err := config.Load(common.configPath)
	if err != nil {
		fmt.Fprintf(stdout, "Config %s: INVALID\n%v\n", common.configPath, err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "Config:     %s\n", common.configPath)

	host := pluginhost.New(cfg, log)
	defer host.Close()

	var client connector.CertGetter
	extra := 0
	switch {
	case *offline:
		fmt.Fprintln(stdout, "API key:    not checked (--offline)")
	case apiKey == "":
		fmt.Fprintln(stdout, "API key:    PROBLEM: KK_API_KEY is not set")
		extra++
	default:
		fmt.Fprintln(stdout, "API key:    set (KK_API_KEY)")
		client = api.NewClient(cfg.KrakenKey.APIURL, apiKey, userAgent())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if connector.Validate(ctx, cfg, host, client, stdout)+extra > 0 {
		return exitFailed
	}
	return exitOK
}
