package openvpn

import (
	"context"
	"time"
)

// tlsiConn is the abstraction the OpenVPN transport uses over its TLS
// client. The default build (CGO_ENABLED=0, no `with_libssl` tag)
// implements this with crypto/tls.Conn; the libssl build (cgo +
// -tags with_libssl) implements it with transport/openvpn/libssl.Conn
// to pick up DHE-RSA cipher suites that Go's crypto/tls deliberately
// omits.
//
// The surface is exactly the subset of *tls.Conn the transport calls:
// Read/Write/Close (from io.ReadWriteCloser), HandshakeContext, and
// the three deadline setters.
type tlsiConn interface {
	// HandshakeContext blocks until the TLS handshake completes, the
	// context is cancelled, or a fatal error is observed. The libssl
	// path mirrors the contract: the surrounding
	// interruptControlConnOnDone callback closes the underlying
	// ControlConn when ctx fires, which unblocks both implementations
	// uniformly.
	HandshakeContext(ctx context.Context) error

	// Read returns decrypted application data.
	Read(p []byte) (int, error)

	// Write encrypts and emits the supplied plaintext. The return
	// value is the number of plaintext bytes consumed, matching the
	// io.Writer contract.
	Write(p []byte) (int, error)

	// Close releases the TLS state. The transport drops epochs
	// without calling Close (see client.go:243-247), so both
	// implementations must skip close_notify.
	Close() error

	// SetDeadline / SetReadDeadline / SetWriteDeadline forward to the
	// underlying transport. The transport uses these to enforce
	// AUTH_PENDING windows, continuation timeouts, and the 300ms
	// token-probe window inside readTokenPushReply.
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// tlsEpoch wraps a tlsiConn so it can sit inside atomic.Pointer with
// a concrete type parameter. Go's generic Pointer[T] does not accept
// an interface type as the parameter — *T is "pointer to interface",
// not "pointer to whatever implements T". The wrapper's methods
// promote to tlsiConn so callers (Chain of methods on *tlsEpoch) work
// without an explicit dereference.
type tlsEpoch struct {
	tlsiConn
}