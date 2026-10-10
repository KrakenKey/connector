package keyvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/krakenkey/connector/pkg/plugin"
)

// operation names a Key Vault call and the permission it needs, so a 403
// can say what to grant.
type operation struct {
	what string
	// rbac is the Azure RBAC data action.
	rbac string
	// accessPolicy is the vault access policy permission.
	accessPolicy string
}

var (
	opGetPolicy = operation{"read the certificate policy",
		"Microsoft.KeyVault/vaults/certificates/read", "certificate permission Get"}
	opGetCertificate = operation{"read the certificate",
		"Microsoft.KeyVault/vaults/certificates/read", "certificate permission Get"}
	opGetPending = operation{"read the pending certificate request",
		"Microsoft.KeyVault/vaults/certificates/read", "certificate permission Get"}
	opCreate = operation{"create a certificate version",
		"Microsoft.KeyVault/vaults/certificates/create/action", "certificate permission Create"}
	opMerge = operation{"merge the issued certificate",
		"Microsoft.KeyVault/vaults/certificates/create/action", "certificate permission Create"}
	opDeletePending = operation{"delete a pending certificate request",
		"Microsoft.KeyVault/vaults/certificates/update/action", "certificate permission Update"}
	opGetSecret = operation{"read the certificate's secret (private key)",
		"Microsoft.KeyVault/vaults/secrets/getSecret/action", "secret permission Get"}
)

// classify turns an error from the Azure SDK into one of the plugin error
// kinds. It never includes response bodies beyond Key Vault's error code
// and message, which do not carry key material.
func classify(op operation, name string, err error) error {
	if err == nil {
		return nil
	}
	prefix := fmt.Sprintf("%s %q", op.what, name)

	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		if resp := authErr.RawResponse; resp == nil || resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("%w: %s: getting an Azure token failed: %v", plugin.ErrUnavailable, prefix, err)
		}
		return fmt.Errorf("%w: %s: Azure rejected the identity: %v", plugin.ErrPermanent, prefix, err)
	}

	var re *azcore.ResponseError
	if errors.As(err, &re) {
		detail := kvMessage(re)
		switch re.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %s: Key Vault rejected the token (HTTP 401%s); check that the identity is in the vault's tenant",
				plugin.ErrPermanent, prefix, detail)
		case http.StatusForbidden:
			return fmt.Errorf("%w: %s: access denied (HTTP 403%s); grant the identity %s on the vault (Azure RBAC), or %s in the vault access policy",
				plugin.ErrPermanent, prefix, detail, op.rbac, op.accessPolicy)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s: HTTP 404%s", plugin.ErrNotFound, prefix, detail)
		case http.StatusConflict:
			if strings.Contains(detail, "deleted but recoverable") {
				return fmt.Errorf("%w: %s: the certificate is soft-deleted in Key Vault (HTTP 409%s); recover or purge it, or use another certificate_name",
					plugin.ErrPermanent, prefix, detail)
			}
			return fmt.Errorf("%w: %s: conflict (HTTP 409%s)", plugin.ErrUnavailable, prefix, detail)
		case http.StatusTooManyRequests, http.StatusRequestTimeout:
			return fmt.Errorf("%w: %s: Key Vault is throttling requests (HTTP %d%s)", plugin.ErrUnavailable, prefix, re.StatusCode, detail)
		}
		if re.StatusCode >= 500 {
			return fmt.Errorf("%w: %s: Key Vault error (HTTP %d%s)", plugin.ErrUnavailable, prefix, re.StatusCode, detail)
		}
		return fmt.Errorf("%w: %s: Key Vault refused the request (HTTP %d%s)", plugin.ErrPermanent, prefix, re.StatusCode, detail)
	}

	// Credentials that cannot be used at all (no managed identity, no
	// environment settings) return an error marked NonRetriable. The SDK
	// wraps every token error in a NonRetriable wrapper too, so look at
	// the innermost error only.
	if _, ok := innermost(err).(interface{ NonRetriable() }); ok {
		return fmt.Errorf("%w: %s: no usable Azure credential: %v", plugin.ErrPermanent, prefix, err)
	}
	// Timeouts, cancellation and network errors: try again later. The
	// context error is not wrapped, so the core sees UNAVAILABLE.
	return fmt.Errorf("%w: %s: %v", plugin.ErrUnavailable, prefix, err)
}

// kvMessage returns ", <code>: <message>" from a Key Vault error body.
func kvMessage(re *azcore.ResponseError) string {
	out := ""
	if re.ErrorCode != "" {
		out = ", " + re.ErrorCode
	}
	if re.RawResponse == nil {
		return out
	}
	body, err := runtime.Payload(re.RawResponse)
	if err != nil {
		return out
	}
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error.Message == "" {
		return out
	}
	msg := e.Error.Message
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	if out == "" {
		return ": " + msg
	}
	return out + ": " + msg
}

func innermost(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

func isNotFound(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusNotFound
}
