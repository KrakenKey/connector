package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/pkg/plugin"
)

// CertGetter is the API call validate uses.
type CertGetter interface {
	GetCert(ctx context.Context, id int) (*api.Cert, error)
}

// Validate prints a report for every configured certificate and returns
// the number of problems. With api nil the API checks are skipped.
func Validate(ctx context.Context, cfg *config.Config, r Resolver, client CertGetter, w io.Writer) int {
	problems := 0
	warnings := 0
	bad := func(format string, args ...any) {
		problems++
		fmt.Fprintf(w, "    PROBLEM: "+format+"\n", args...)
	}

	fmt.Fprintf(w, "API:        %s\n", cfg.KrakenKey.APIURL)
	fmt.Fprintf(w, "Data dir:   %s\n", cfg.DataDir)
	fmt.Fprintf(w, "Audit log:  %s\n", cfg.AuditLog)
	fmt.Fprintf(w, "Interval:   %s\n", cfg.CheckInterval)
	for _, warn := range cfg.Warnings() {
		warnings++
		fmt.Fprintf(w, "WARNING: %s\n", warn)
	}

	authFailed := false
	for _, cert := range cfg.Certificates {
		fmt.Fprintf(w, "\nCertificate %d [%s]\n", cert.ID, strings.Join(cert.Names, ", "))
		_, rep := BuildJob(ctx, cert, r)

		fmt.Fprintf(w, "  key store %s (%s)", rep.KeyStore, cert.KeyStore.KeyType)
		if c := rep.KeyStoreCaps; c != nil {
			fmt.Fprintf(w, ": provides %s, exportable %t", joinFormats(c.Provides), c.Exportable)
		}
		fmt.Fprintln(w)
		for _, p := range rep.Problems {
			bad("%s", p)
		}

		for i, t := range rep.Targets {
			fmt.Fprintf(w, "  target %s (%s)", t.Label, t.Plugin)
			if t.Format != "" {
				fmt.Fprintf(w, ": key as %s", t.Format)
			}
			if t.Caps != nil {
				rollback := "rollback supported"
				switch {
				case t.Caps.PropagatesAsync:
					rollback = "propagates on its own schedule, not rolled back"
				case !t.Caps.SupportsRollback:
					rollback = "no rollback"
				case t.RollbackUnavailable != "":
					rollback = "rollback unavailable"
				case t.Caps.RollbackNeedsMaterial:
					rollback = "rollback supported (with the previous certificate and key from the connector)"
				}
				fmt.Fprintf(w, ", %s", rollback)
			}
			fmt.Fprintln(w)
			for _, p := range t.Problems {
				bad("%s", p)
			}
			for _, warn := range t.Warnings {
				warnings++
				fmt.Fprintf(w, "    WARNING: %s\n", warn)
			}
			tc := cert.Targets[i]
			if t.Plugin != "" && t.Caps != nil {
				if tg, err := r.Target(t.Plugin); err == nil {
					settings, _ := tc.SettingsJSON()
					if cur, err := tg.Current(ctx, plugin.CurrentRequest{Config: settings, CertificateID: strconv.Itoa(cert.ID), Label: tc.Label}); err == nil && cur != "" {
						fmt.Fprintf(w, "    installed now: serial %s\n", cur)
					}
				}
			}
			if tc.Then != nil {
				fmt.Fprintf(w, "    then: %s (timeout %s)\n", strings.Join(tc.Then.Exec, " "), tc.Then.Timeout)
			}
			if v := tc.Verify; v != nil {
				chain := "chain checked against system roots"
				switch {
				case v.SkipChainValidation:
					chain = "chain NOT validated (skip_chain_validation)"
				case v.CAFile != "":
					chain = "chain checked against " + v.CAFile
				}
				fmt.Fprintf(w, "    verify: TLS to %s with SNI %s, window %s, %s\n", v.DialAddress(), v.Host, t.Window, chain)
			} else {
				fmt.Fprintf(w, "    verify: none\n")
			}
		}

		if client == nil || authFailed {
			continue
		}
		c, err := client.GetCert(ctx, cert.ID)
		var authErr *api.AuthError
		var connAuthErr *api.ConnectorAuthError
		var nf *api.NotFoundError
		switch {
		case errors.As(err, &authErr), errors.As(err, &connAuthErr):
			authFailed = true
			bad("%v", err)
			continue
		case errors.As(err, &nf):
			bad("KrakenKey has no certificate %d that these credentials can see", cert.ID)
			continue
		case err != nil:
			bad("KrakenKey API: %v", err)
			continue
		}
		if c.Status == api.StatusAwaitingCSR {
			fmt.Fprintf(w, "  KrakenKey: status %s: waiting for this connector to issue it (the first pass sends the CSR)\n", c.Status)
			switch {
			case len(c.RequestedNames) == 0:
				bad("KrakenKey did not say which names certificate %d is for (no requestedNames)", cert.ID)
			case !certutil.SameNames(c.RequestedNames, cert.Names):
				bad("config names %v differ from the names KrakenKey is waiting for %v",
					certutil.NormalizeNames(cert.Names), certutil.NormalizeNames(c.RequestedNames))
			}
			continue
		}
		fmt.Fprintf(w, "  KrakenKey: status %s", c.Status)
		if c.ExpiresAt != nil {
			fmt.Fprintf(w, ", expires %s", c.ExpiresAt.UTC().Format(time.RFC3339))
		}
		if at, source, ok := c.RenewAt(); ok {
			fmt.Fprintf(w, ", renew after %s (%s)", at.UTC().Format(time.RFC3339), source)
		} else {
			fmt.Fprint(w, ", renewal time unknown")
		}
		fmt.Fprintln(w)
		if c.AutoRenew {
			warnings++
			fmt.Fprintf(w, "  WARNING: KrakenKey also renews certificate %d on its own (autoRenew is on). The connector adopts those renewals, but turn auto-renewal off so renewals happen only on the connector's schedule.\n", cert.ID)
		}
		if c.ManagedBy != nil && *c.ManagedBy != "connector" {
			warnings++
			fmt.Fprintf(w, "  WARNING: KrakenKey reports certificate %d as managed by %q, not by a connector.\n", cert.ID, *c.ManagedBy)
		}
		if c.Status == api.StatusRevoked {
			bad("certificate %d is revoked", cert.ID)
		}
		if c.CrtPem != "" {
			if leaf, err := certutil.ParseLeaf(c.CrtPem); err == nil && !certutil.SameNames(certutil.CertNames(leaf), cert.Names) {
				bad("config names %v differ from the certificate's names %v; KrakenKey renews with the same names",
					certutil.NormalizeNames(cert.Names), certutil.NormalizeNames(certutil.CertNames(leaf)))
			}
		}
	}

	fmt.Fprintf(w, "\n%d problem(s), %d warning(s)\n", problems, warnings)
	return problems
}

func joinFormats(fs []plugin.KeyFormat) string {
	s := make([]string, len(fs))
	for i, f := range fs {
		s[i] = string(f)
	}
	return strings.Join(s, ", ")
}
