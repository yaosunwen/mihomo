//go:build !with_libssl

package openvpn

import (
	"net"

	"github.com/metacubex/tls"
)

// newTLSConn constructs a *crypto/tls.Conn-backed tlsiConn. The default
// build uses Go's crypto/tls; this is the surface that already exists
// upstream and continues to ship with the unmodified CGO_ENABLED=0
// release binaries.
//
// The build-tag sibling tlsconn_cgo.go provides the libssl-backed
// implementation under `-tags with_libssl` + CGO_ENABLED=1.
func newTLSConn(transport net.Conn, cfg *ClientConfig) (tlsiConn, error) {
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return tls.Client(transport, tlsConfig), nil
}

// verifyPeerFromConn is a no-op on the crypto/tls path: the verify
// closure registered in buildTLSConfig runs inside HandshakeContext, so
// by the time this helper is called the chain has already been
// validated.
func verifyPeerFromConn(tlsiConn, []byte) error { return nil }

// tlsConfigFromClient is an alias kept for backward compatibility.
func tlsConfigFromClient(cfg *ClientConfig) (*tls.Config, error) {
	return buildTLSConfig(cfg)
}