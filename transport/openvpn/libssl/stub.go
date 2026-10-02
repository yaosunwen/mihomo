//go:build !darwin || !with_libssl

// Package libssl is an optional cgo + libssl replacement for the Go
// crypto/tls client used by the OpenVPN transport. It is only built when
// the `with_libssl` build tag is supplied on darwin AND cgo is enabled
// (CGO_ENABLED=1).
//
// Without the tag, the package exposes stub symbols so the surrounding
// transport/openvpn package continues to compile unchanged and the upstream
// default build (CGO_ENABLED=0) is preserved.
package libssl

import (
	"context"
	"errors"
	"net"
	"time"
)

// ErrNotBuilt is returned by every method on the stub implementation. The
// accompanying message points at the build flag that switches the cgo
// implementation on.
var ErrNotBuilt = errors.New(
	"openvpn libssl wrapper not built: rebuild with -tags with_libssl and CGO_ENABLED=1; " +
		"this stub preserves the default crypto/tls path used by upstream mihomo",
)

// Config mirrors the small subset of *tls.Config that the OpenVPN
// transport requires when constructing the cgo client. The stub does not
// read the fields; only the cgo build consults them.
type Config struct {
	RootPEM []byte
	CertPEM []byte
	KeyPEM  []byte
}

// Conn is the stub counterpart of the cgo-backed TLS connection. All
// methods return ErrNotBuilt.
type Conn struct{}

// NewClient always returns ErrNotBuilt when the cgo implementation is
// absent. The transport layer should treat this as a fatal configuration
// error: the operator asked for the libssl path but did not build with
// the appropriate tag.
func NewClient(net.Conn, *Config) (*Conn, error) {
	return nil, ErrNotBuilt
}

// HandshakeContext implements the net.Conn subset required by the
// OpenVPN transport. The stub returns ErrNotBuilt; the transport does
// not call this method when the cgo build is selected.
func (*Conn) HandshakeContext(context.Context) error { return ErrNotBuilt }

// Read is a stub and returns ErrNotBuilt.
func (*Conn) Read([]byte) (int, error) { return 0, ErrNotBuilt }

// Write is a stub and returns ErrNotBuilt.
func (*Conn) Write([]byte) (int, error) { return 0, ErrNotBuilt }

// Close is a stub; it returns ErrNotBuilt to match the other stubs. In
// practice the transport never closes the libssl wrapper.
func (*Conn) Close() error { return ErrNotBuilt }

// SetDeadline is a stub. Returning ErrNotBuilt mirrors the other
// deadline setters below; the transport's existing
// `interruptControlConnOnDone` path does not require libssl to honour a
// deadline directly.
func (*Conn) SetDeadline(time.Time) error { return ErrNotBuilt }

// SetReadDeadline is a stub.
func (*Conn) SetReadDeadline(time.Time) error { return ErrNotBuilt }

// SetWriteDeadline is a stub. The stub keeps the method set symmetric
// with the cgo Conn, even though the transport only calls
// SetDeadline / SetReadDeadline.
func (*Conn) SetWriteDeadline(time.Time) error { return ErrNotBuilt }