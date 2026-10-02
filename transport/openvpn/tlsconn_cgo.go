//go:build darwin && with_libssl

package openvpn

import (
	"crypto/x509"
	"errors"
	"net"

	"github.com/metacubex/mihomo/transport/openvpn/libssl"
)

// newTLSConn builds a libssl-backed tlsiConn over transport. The libssl
// build enables the DHE-RSA cipher suites that Go's crypto/tls
// deliberately omits (golang/go#7758); without this path the OpenVPN
// server at 45.33.95.168:443 (via stunnel) rejects the ClientHello
// with close_notify and mihomo reports "openvpn tls handshake: EOF".
//
// The cert/key/CA wire format is unchanged from the crypto/tls path:
// the same PEM blocks feed libssl.Config, which mirrors
// crypto/tls.Config's CA + certificate usage one-to-one.
func newTLSConn(transport net.Conn, cfg *ClientConfig) (tlsiConn, error) {
	libsslCfg := &libssl.Config{
		RootPEM: cfg.CA,
		CertPEM: cfg.Cert,
		KeyPEM:  cfg.Key,
	}
	conn, err := libssl.NewClient(transport, libsslCfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// verifyPeerFromConn runs the same x509.Verify policy that
// crypto/tls's VerifyConnection callback would have applied, but does
// it explicitly after HandshakeContext returns. The libssl Conn has no
// in-handshake verify hook that gives us a Go-side
// []*x509.Certificate to pass to crypto/x509.Verify, hence the explicit
// post-handshake step here.
//
// The transport calls this once per epoch right after
// HandshakeContext succeeds.
func verifyPeerFromConn(conn tlsiConn, caPEM []byte) error {
	peer, ok := conn.(interface {
		PeerCertificates() ([]*x509.Certificate, error)
	})
	if !ok {
		// Should never happen on the libssl build path, but the type
		// assertion is the cleanest way to keep the interface clean
		// for callers that don't need this hook (the nocgo path).
		return errors.New("openvpn libssl conn does not expose PeerCertificates")
	}
	certs, err := peer.PeerCertificates()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("openvpn server did not provide certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("parse openvpn ca certificate")
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	return nil
}