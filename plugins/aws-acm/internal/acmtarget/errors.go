package acmtarget

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/smithy-go"

	"github.com/krakenkey/connector/pkg/plugin"
)

// errCertNotFound marks a ResourceNotFoundException. It is not
// plugin.ErrNotFound, which means a staged or previous ref is unknown.
var errCertNotFound = errors.New("the certificate does not exist")

// Error codes AWS returns when the caller's credentials or permissions are
// the problem. Retrying does not help until someone changes the policy.
var deniedCodes = map[string]bool{
	"AccessDeniedException":       true,
	"AccessDenied":                true,
	"UnauthorizedOperation":       true,
	"UnrecognizedClientException": true,
	"InvalidClientTokenId":        true,
	"InvalidSignatureException":   true,
	"SignatureDoesNotMatch":       true,
	"MissingAuthenticationToken":  true,
	"IncompleteSignature":         true,
}

// Error codes for conditions that pass on their own.
var transientCodes = map[string]bool{
	"ThrottlingException":         true,
	"Throttling":                  true,
	"TooManyRequestsException":    true,
	"RequestLimitExceeded":        true,
	"RequestInProgressException":  true,
	"InternalServerException":     true,
	"InternalFailure":             true,
	"ServiceUnavailable":          true,
	"ServiceUnavailableException": true,
	"RequestTimeout":              true,
	"RequestTimeoutException":     true,
	"ExpiredTokenException":       true,
	"RequestExpired":              true,
}

// mapErr turns an ACM SDK error into an error wrapping one of the plugin
// error kinds, naming the IAM action so a permission problem is easy to
// fix. AWS error messages do not carry the request body, so no key
// material can end up here.
func mapErr(action, certARN string, err error) error {
	if err == nil {
		return nil
	}
	op := "acm:" + action + " on " + certARN
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: %w", op, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %s: timed out; will retry", plugin.ErrUnavailable, op)
	}
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		// No answer from ACM: network trouble, or no credentials could be
		// loaded yet (for example the instance metadata service is slow).
		return fmt.Errorf("%w: %s: %v", plugin.ErrUnavailable, op, err)
	}
	code, msg := ae.ErrorCode(), ae.ErrorMessage()
	switch {
	case deniedCodes[code]:
		return fmt.Errorf("%w: AWS denied %s (%s: %s); allow %s for the connector's credentials",
			plugin.ErrPermanent, op, code, msg, "acm:"+action)
	case transientCodes[code]:
		return fmt.Errorf("%w: %s: %s: %s", plugin.ErrUnavailable, op, code, msg)
	case code == "ResourceNotFoundException":
		return fmt.Errorf("%w: %s: %w (%s)", plugin.ErrPermanent, op, errCertNotFound, msg)
	default:
		return fmt.Errorf("%w: %s: %s: %s", plugin.ErrPermanent, op, code, msg)
	}
}

// isAPIError reports whether ACM answered the request, so its outcome is
// known.
func isAPIError(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae)
}
