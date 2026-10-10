package plugin

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error kinds. Plugin implementations wrap these so the core knows how to
// react, for example:
//
//	return fmt.Errorf("%w: key %s is not exportable", plugin.ErrPermanent, ref)
//
// They map to gRPC status codes as described in plugin.proto, and the host
// side maps them back, so errors.Is works on both sides of the connection.
var (
	// ErrUnsupported means the plugin does not implement the call
	// (codes.Unimplemented). Optional calls that return it are skipped.
	ErrUnsupported = errors.New("not supported by this plugin")
	// ErrPermanent means retrying the same call will not help
	// (codes.FailedPrecondition).
	ErrPermanent = errors.New("permanent failure")
	// ErrInvalid means the request is malformed (codes.InvalidArgument).
	ErrInvalid = errors.New("invalid request")
	// ErrNotFound means a key, staged or previous reference does not exist
	// (codes.NotFound).
	ErrNotFound = errors.New("not found")
	// ErrUnavailable means a transient failure worth retrying later
	// (codes.Unavailable).
	ErrUnavailable = errors.New("temporarily unavailable")
)

// IsPermanent reports whether retrying err later is pointless.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent) || errors.Is(err, ErrInvalid)
}

// IsUnsupported reports whether err means the plugin does not implement a
// call.
func IsUnsupported(err error) bool { return errors.Is(err, ErrUnsupported) }

var kindCodes = []struct {
	kind error
	code codes.Code
}{
	{context.Canceled, codes.Canceled},
	{context.DeadlineExceeded, codes.DeadlineExceeded},
	{ErrUnsupported, codes.Unimplemented},
	{ErrPermanent, codes.FailedPrecondition},
	{ErrInvalid, codes.InvalidArgument},
	{ErrNotFound, codes.NotFound},
	{ErrUnavailable, codes.Unavailable},
}

// toStatus turns an implementation error into a gRPC status. Errors that
// already are statuses pass through unchanged.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	for _, kc := range kindCodes {
		if errors.Is(err, kc.kind) {
			return status.Error(kc.code, err.Error())
		}
	}
	return status.Error(codes.Unknown, err.Error())
}

// rpcError is a plugin error on the host side. Its message is the plugin's
// message without the "rpc error: code = ..." prefix, and it unwraps to the
// matching error kind.
type rpcError struct {
	op   string
	msg  string
	kind error
}

func (e *rpcError) Error() string { return e.op + ": " + e.msg }
func (e *rpcError) Unwrap() error { return e.kind }

// fromStatus turns a gRPC error back into an error that carries the
// plugin's message and unwraps to the error kind for its code.
func fromStatus(op string, err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", op, err)
	}
	e := &rpcError{op: op, msg: st.Message()}
	for _, kc := range kindCodes {
		if st.Code() == kc.code {
			e.kind = kc.kind
		}
	}
	switch st.Code() {
	case codes.Unimplemented:
		e.msg = "plugin does not implement this call: " + st.Message()
	case codes.Unavailable:
		e.msg = "plugin unavailable: " + st.Message()
	}
	return e
}
