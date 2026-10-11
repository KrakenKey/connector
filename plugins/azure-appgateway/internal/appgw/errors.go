package appgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Permission hints for 403 answers. The denied action Azure names is added
// to the error; these say where to grant it.
const (
	readPermission  = "the connector's Azure identity needs Microsoft.Network/applicationGateways/read on the gateway"
	writePermission = "the connector's Azure identity needs Microsoft.Network/applicationGateways/write on the gateway, " +
		"Microsoft.ManagedIdentity/userAssignedIdentities/assign/action on the gateway's managed identity, and read plus " +
		"join/action on the gateway's subnet, public IP address and WAF policy (see the plugin README for the role)"
)

// opKind says which ARM call failed, for messages and permission hints.
type opKind int

const (
	opRead opKind = iota
	opUpdate
)

// armError describes an ARM error response in one line. It keeps the
// status, the error code and the actions Azure says were denied, but not
// Azure's message: for a denied request it names the caller's object and
// application ids, its tenant and the resource's subscription, which must
// not end up in logs or status reports.
type armError struct {
	Status int
	Code   string
	// Denied lists the actions the message says the caller may not
	// perform, such as Microsoft.Network/applicationGateways/write.
	Denied []string
}

func (e armError) String() string {
	// A failed long-running operation comes back as HTTP 200 with an
	// error body; the status adds nothing there.
	var s string
	if e.Status != http.StatusOK {
		s = fmt.Sprintf("HTTP %d", e.Status)
	}
	if e.Code != "" {
		s = strings.TrimSpace(s + " " + e.Code)
	}
	if len(e.Denied) > 0 {
		s += ", denied action " + strings.Join(e.Denied, " and ")
	}
	return s
}

// responseError extracts the status, code and message from an azcore
// response error. ok is false for other errors.
func responseError(err error) (armError, bool) {
	var re *azcore.ResponseError
	if !errors.As(err, &re) {
		return armError{}, false
	}
	ae := armError{Status: re.StatusCode, Code: re.ErrorCode}
	if re.RawResponse != nil {
		if body, rerr := runtime.Payload(re.RawResponse); rerr == nil {
			var msg string
			ae.Code, msg = errorBody(body, ae.Code)
			ae.Denied = deniedActions(msg)
		}
	}
	return ae, true
}

// deniedRE finds the actions in ARM authorization failures: "does not have
// authorization to perform action 'X'" and, for linked resources, "does not
// have permission to perform action 'X'".
var deniedRE = regexp.MustCompile(`does not have (?:authorization|permission) to perform action '([A-Za-z0-9./_-]+)'`)

func deniedActions(msg string) []string {
	var out []string
	for _, m := range deniedRE.FindAllStringSubmatch(msg, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

var (
	aadCodeRE = regexp.MustCompile(`AADSTS[0-9]+`)
	guidRE    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	issuerRE  = regexp.MustCompile(`https://sts\.windows\.net/[^\s/]+/?`)
)

// scrub removes what identifies the caller, its tenant or subscription
// from error text that comes from the Azure SDK: GUIDs and token issuer
// URLs. The same helper lives in the azure-keyvault plugin; plugin modules
// share only the core module.
func scrub(s string) string {
	s = issuerRE.ReplaceAllString(s, "<issuer>")
	return guidRE.ReplaceAllString(s, "<id>")
}

// credentialError describes a failure to get a token: the HTTP status and
// the Microsoft Entra error code (AADSTS...), nothing else from the answer.
// ok is false for other errors.
func credentialError(err error) (msg string, transient, ok bool) {
	var authErr *azidentity.AuthenticationFailedError
	if !errors.As(err, &authErr) {
		return "", false, false
	}
	resp := authErr.RawResponse
	if resp == nil {
		return "getting an Azure token failed", true, true
	}
	detail := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if code := aadCodeRE.FindString(err.Error()); code != "" {
		detail += ", " + code
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return "getting an Azure token failed (" + detail + ")", true, true
	}
	return "Azure rejected the credential (" + detail + ")", false, true
}

// errorBody reads the ARM error envelope ({"error":{"code","message"}}),
// which both direct responses and failed operation status bodies use.
func errorBody(body []byte, code string) (string, string) {
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) != nil || env.Error == nil {
		return code, ""
	}
	if env.Error.Code != "" {
		code = env.Error.Code
	}
	return code, env.Error.Message
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// classify turns an error from an ARM call into one wrapping the plugin
// error kind the core acts on. Context expiry becomes ErrUnavailable so the
// core retries on a later pass instead of treating it as its own deadline.
func classify(op opKind, cfg Config, err error) error {
	what := "reading"
	if op == opUpdate {
		what = "updating"
	}
	where := fmt.Sprintf("%s application gateway %s/%s", what, cfg.ResourceGroup, cfg.Gateway)

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: timed out: %s", plugin.ErrUnavailable, where, scrub(err.Error()))
	}
	if msg, transient, ok := credentialError(err); ok {
		kind := plugin.ErrPermanent
		if transient {
			kind = plugin.ErrUnavailable
		}
		return fmt.Errorf("%w: %s: %s", kind, where, msg)
	}
	ae, ok := responseError(err)
	if !ok {
		// Network errors, credential errors and the like.
		return fmt.Errorf("%w: %s: %s", plugin.ErrUnavailable, where, scrub(oneLine(err.Error())))
	}
	switch {
	case ae.Status == http.StatusForbidden:
		hint := readPermission
		if op == opUpdate {
			hint = writePermission
		}
		return fmt.Errorf("%w: %s: permission denied (%s); %s", plugin.ErrPermanent, where, ae, hint)
	case ae.Status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %s: Azure rejected the credential (%s)", plugin.ErrPermanent, where, ae)
	case ae.Status == http.StatusNotFound:
		return fmt.Errorf("%w: %s: not found (%s); check subscription_id, resource_group and gateway", plugin.ErrPermanent, where, ae)
	case ae.Status == http.StatusConflict:
		// Usually AnotherOperationInProgress: the gateway is being updated.
		return fmt.Errorf("%w: %s: conflict (%s)", plugin.ErrUnavailable, where, ae)
	case ae.Status == http.StatusTooManyRequests, ae.Status == http.StatusRequestTimeout, ae.Status >= 500:
		return fmt.Errorf("%w: %s: %s", plugin.ErrUnavailable, where, ae)
	case ae.Status >= 400:
		return fmt.Errorf("%w: %s: %s", plugin.ErrPermanent, where, ae)
	default:
		// A failed long-running operation: the status poll answered 200 with
		// status Failed. Most such failures are worth another try later.
		return fmt.Errorf("%w: %s: the update failed (%s)", plugin.ErrUnavailable, where, ae)
	}
}

func isStatus(err error, status int) bool {
	ae, ok := responseError(err)
	return ok && ae.Status == status
}
