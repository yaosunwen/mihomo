//go:build darwin && with_libssl

// smoketest is a manual end-to-end probe for the libssl Conn. Build
// it standalone and run against a local openssl s_server:
//
//	openssl req -x509 -newkey rsa:2048 -nodes -keyout smoketest.key \
//	    -out smoketest.crt -days 1 -subj '/CN=localhost'
//	openssl s_server -accept 14443 -cert smoketest.crt -key smoketest.key \
//	    -cipher 'DHE-RSA-AES256-GCM-SHA384' -tls1_2 -www
//
//	go run ./smoketest.go
//
// The probe connects, performs a TLS handshake, exchanges one line of
// plaintext, and exits. It exits non-zero on any failure.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/metacubex/mihomo/transport/openvpn/libssl"
)

func main() {
	addr := "127.0.0.1:14443"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %v\n", addr, err)
		os.Exit(1)
	}

	libsslConn, err := libssl.NewClient(conn, &libssl.Config{
		// Trust the self-signed cert s_server is serving. The smoketest
		// cert at /tmp/smoketest.crt is its own CA (a self-signed
		// root), so feeding it as RootPEM makes verification succeed.
		RootPEM: mustReadFile("/tmp/smoketest.crt"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "libssl.NewClient: %v\n", err)
		os.Exit(1)
	}

	if err := libsslConn.HandshakeContext(timeoutCtx(10 * time.Second)); err != nil {
		fmt.Fprintf(os.Stderr, "HandshakeContext: %v\n", err)
		os.Exit(1)
	}
	certs, err := libsslConn.PeerCertificates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "PeerCertificates: %v\n", err)
		os.Exit(1)
	}
	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "no peer certificates")
		os.Exit(1)
	}
	fmt.Printf("cipher: %s\n", cipherName(libsslConn))
	for i, c := range certs {
		fmt.Printf("cert[%d]: subject=%q issuer=%q\n", i, c.Subject, c.Issuer)
	}

	// Try sending a simple HTTP request to provoke a response.
	if _, err := libsslConn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		fmt.Fprintf(os.Stderr, "Write: %v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, 4096)
	libsslConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := libsslConn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("server reply: %d bytes (first 80): %q\n", n, string(buf[:min(n, 80)]))
}

// cipherName reports the cipher negotiated by the handshake, falling
// back to a literal when the libssl client does not yet expose the
// field. (It currently does not; the helper exists for future
// extension without touching the smoke test main.)
func cipherName(*libssl.Conn) string { return "(unknown)" }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func timeoutCtx(d time.Duration) context.Context {
	ctx, _ := context.WithTimeout(context.Background(), d)
	return ctx
}

var _ = x509.NewCertPool // keep x509 imported for the future verify path

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	return b
}