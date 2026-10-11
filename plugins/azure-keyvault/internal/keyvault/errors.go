package keyvault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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
	// Key Vault asks for certificate permission Create to read a pending
	// request in vaults that use access policies.
	opGetPending = operation{"read the pending certificate request",
		"Microsoft.KeyVault/vaults/certificates/read", "certificate permissions Get and Create"}
	opCreate = operation{"create a certificate version",
		"Microsoft.KeyVault/vaults/certificates/create/action", "certificate permission Create"}
	opMerge = operation{"merge the issued certificate",
		"Microsoft.KeyVault/vaults/certificates/create/action", "certificate permission Create"}
	opDeletePending = operation{"delete a pending certificate request",
		"Microsoft.KeyVault/vaults/certificates/update/action", "certificate permission Update"}
	opGetSecret = operation{"read the certificate's secret (private key)",
		"Microsoft.KeyVault/vaults/secrets/getSecret/action", "secret permission Get"}
	opUpdateTags = operation{"tag the certificate version",
		"Microsoft.KeyVault/vaults/certificates/update/action", "certificate permission Update"}
	opImport = operation{"import a certificate version",
		"Microsoft.KeyVault/vaults/certificates/import/action", "certificate permission Import"}
	opListVersions = operation{"list the certificate's versions",
		"Microsoft.KeyVault/vaults/certificates/read", "certificate permission List"}
)

// Key Vault error codes (error.code or error.innererror.code) that get
// their own message.
const (
	codeDeletedButRecoverable = "ObjectIsDeletedButRecoverable"
	codeSecretDisabled        = "SecretDisabled"
	codeCertificateDisabled   = "CertificateDisabled"
	codeKeyDisabled           = "KeyDisabled"
)

// kvError is the body of a Key Vault error response. Only the codes are
// put into errors: Key Vault's message for a denied request names the
// caller (application and object ids, tenant), which must not end up in
// logs or in status reports.
type kvError struct {
	Code  string
	Inner string
	// Permission and Action are what the message says is missing: an
	// access policy permission ("certificates create") or an RBAC data
	// action. Empty when the message names none.
	Permission string
	Action     string
}

// hasCode reports whether the error or its inner error has code.
func (e kvError) hasCode(code string) bool { return e.Code == code || e.Inner == code }

// detail renders ", <code>/<inner code>" for error messages.
func (e kvError) detail() string {
	out := ""
	if e.Code != "" {
		out = ", " + e.Code
	}
	if e.Inner != "" {
		out += "/" + e.Inner
	}
	return out
}

var (
	// "... does not have certificates create permission on key vault ..."
	permissionRE = regexp.MustCompile(`does not have (certificates|secrets|keys) ([a-zA-Z]+) permission`)
	// "... Action: 'Microsoft.KeyVault/vaults/certificates/read' ..."
	actionRE = regexp.MustCompile(`Action: '(Microsoft\.KeyVault/[A-Za-z/]+)'`)
)

func parseKVError(re *azcore.ResponseError) kvError {
	e := kvError{Code: re.ErrorCode}
	if re.RawResponse == nil {
		return e
	}
	body, err := runtime.Payload(re.RawResponse)
	if err != nil {
		return e
	}
	var b struct {
		Error struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			InnerError *struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &b) != nil {
		return e
	}
	if b.Error.Code != "" {
		e.Code = b.Error.Code
	}
	if b.Error.InnerError != nil {
		e.Inner = b.Error.InnerError.Code
	}
	if m := permissionRE.FindStringSubmatch(b.Error.Message); m != nil {
		e.Permission = m[1] + " " + strings.ToLower(m[2])
	}
	if m := actionRE.FindStringSubmatch(b.Error.Message); m != nil {
		e.Action = m[1]
	}
	return e
}

// responseError returns the Key Vault response error in err, if any.
func responseError(err error) (*azcore.ResponseError, kvError, bool) {
	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		return nil, kvError{}, false
	}
	return re, parseKVError(re), true
}

// classify turns an error from the Azure SDK into one of the plugin error
// kinds. It never includes response bodies beyond Key Vault's error codes
// and message, which do not carry key material.
func classify(op operation, name string, err error) error {
	if err == nil {
		return nil
	}
	prefix := fmt.Sprintf("%s %q", op.what, name)

	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		detail := ""
		if resp := authErr.RawResponse; resp != nil {
			detail = fmt.Sprintf(" (HTTP %d", resp.StatusCode)
			if code := aadCodeRE.FindString(err.Error()); code != "" {
				detail += ", " + code
			}
			detail += ")"
		}
		if resp := authErr.RawResponse; resp == nil || resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("%w: %s: getting an Azure token failed%s", plugin.ErrUnavailable, prefix, detail)
		}
		return fmt.Errorf("%w: %s: Azure rejected the identity%s", plugin.ErrPermanent, prefix, detail)
	}

	if re, kv, ok := responseError(err); ok {
		detail := kv.detail()
		switch {
		case kv.hasCode(codeDeletedButRecoverable):
			return fmt.Errorf("%w: %s: the certificate is soft-deleted in Key Vault (HTTP %d%s); recover or purge it, or use another certificate_name",
				plugin.ErrPermanent, prefix, re.StatusCode, detail)
		case kv.hasCode(codeSecretDisabled), kv.hasCode(codeCertificateDisabled), kv.hasCode(codeKeyDisabled):
			return fmt.Errorf("%w: %s: this version is disabled in Key Vault (HTTP %d%s); enable it again while a target still uses it",
				plugin.ErrPermanent, prefix, re.StatusCode, detail)
		}
		switch re.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %s: Key Vault rejected the token (HTTP 401%s); check that the identity is in the vault's tenant",
				plugin.ErrPermanent, prefix, detail)
		case http.StatusForbidden:
			// Name what Key Vault says is missing when it says so; it can
			// differ from what the operation is expected to need.
			rbac, policy := op.rbac, op.accessPolicy
			if kv.Action != "" {
				rbac = kv.Action
			}
			if kv.Permission != "" {
				kind, perm, _ := strings.Cut(kv.Permission, " ")
				policy = strings.TrimSuffix(kind, "s") + " permission " + strings.ToUpper(perm[:1]) + perm[1:]
			}
			return fmt.Errorf("%w: %s: access denied (HTTP 403%s); grant the identity %s on the vault (Azure RBAC), or %s in the vault access policy",
				plugin.ErrPermanent, prefix, detail, rbac, policy)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s: HTTP 404%s", plugin.ErrNotFound, prefix, detail)
		case http.StatusConflict:
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
		return fmt.Errorf("%w: %s: no usable Azure credential: %s", plugin.ErrPermanent, prefix, scrub(err.Error()))
	}
	// Timeouts, cancellation and network errors: try again later. The
	// context error is not wrapped, so the core sees UNAVAILABLE.
	return fmt.Errorf("%w: %s: %s", plugin.ErrUnavailable, prefix, scrub(err.Error()))
}

var (
	aadCodeRE = regexp.MustCompile(`AADSTS[0-9]+`)
	guidRE    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	issuerRE  = regexp.MustCompile(`https://sts\.windows\.net/[^\s/]+/?`)
)

// scrub removes what identifies the caller or its tenant from error text
// that comes from the Azure SDK: GUIDs (application, object, tenant and
// request ids) and token issuer URLs.
func scrub(s string) string {
	s = issuerRE.ReplaceAllString(s, "<issuer>")
	return guidRE.ReplaceAllString(s, "<id>")
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

func hasStatus(err error, status int) bool {
	re, _, ok := responseError(err)
	return ok && re.StatusCode == status
}

func isNotFound(err error) bool { return hasStatus(err, http.StatusNotFound) }
