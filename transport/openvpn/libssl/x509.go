//go:build darwin && with_libssl

package libssl

/*
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include <stdlib.h>
#include <string.h>
#include "libssl_helpers.c"
*/
import "C"

import (
	"crypto/x509"
	"fmt"
	"runtime"
	"unsafe"
)

// peerCertificates walks the chain OpenSSL observed during the most
// recent handshake and returns it as a slice of Go *x509.Certificate.
//
// The leaf is fetched via SSL_get1_peer_certificate (which bumps the
// refcount; we X509_free it after marshalling to DER). The rest of the
// chain comes from SSL_get_peer_cert_chain; the returned STACK_OF(X509)
// is owned by the SSL struct and is only valid for the lifetime of the
// handshake. We marshal every X509 to DER immediately so the slice we
// hand the transport is fully decoupled from the SSL state.
//
// The transport calls this once after HandshakeContext returns nil.
// The certificate objects returned here are then passed to the same
// x509.Verify call that crypto/tls's VerifyConnection would have
// triggered.
func peerCertificates(ssl *C.SSL) ([]*x509.Certificate, error) {
	// LockOSThread keeps the SSL_get1_peer_certificate /
	// SSL_get_peer_cert_chain sequence on a single OS thread. This
	// matches the threading discipline used by every cgo + libssl
	// wrapper, even when the surface is otherwise goroutine-safe.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	leaf := C.SSL_get1_peer_certificate(ssl)
	if leaf == nil {
		return nil, fmt.Errorf("SSL_get1_peer_certificate returned NULL")
	}
	defer C.X509_free(leaf)

	chainStack := C.SSL_get_peer_cert_chain(ssl)
	if chainStack == nil {
		// Some servers send only the leaf; treat that as a one-element
		// chain so the verifier can still produce a meaningful error.
		der, err := marshalX509(leaf)
		if err != nil {
			return nil, fmt.Errorf("marshal peer leaf: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse peer leaf: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}

	n := int(C.ssl_sk_X509_num(chainStack))
	out := make([]*x509.Certificate, 0, n)
	// First slot is the leaf per OpenSSL convention. Marshal the leaf
	// first so intermediate certificates end up at indexes >= 1 in the
	// returned slice, matching the order crypto/tls uses for its
	// ConnectionState.PeerCertificates field (and matching the layout
	// transport/openvpn/client.go:1750-1757 indexes into).
	leafDER, err := marshalX509(leaf)
	if err != nil {
		return nil, fmt.Errorf("marshal peer leaf: %w", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parse peer leaf: %w", err)
	}
	out = append(out, leafCert)
	for i := 0; i < n; i++ {
		cert := C.ssl_sk_X509_value(chainStack, C.int(i))
		if cert == nil {
			continue
		}
		der, err := marshalX509(cert)
		if err != nil {
			return nil, fmt.Errorf("marshal chain[%d]: %w", i, err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse chain[%d]: %w", i, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

// marshalX509 serializes an OpenSSL X509 into DER bytes that the Go
// x509 package can parse. We use i2d_X509 with a NULL output pointer
// to learn the required length, then call i2d_X509 a second time with
// an OpenSSL-malloc'd scratch buffer and copy the result into a
// Go-owned slice. We cannot write directly into a Go slice because
// cgo's pointer checker rejects Go pointers reaching the C boundary.
func marshalX509(cert *C.X509) ([]byte, error) {
	// First pass: figure out the size. Pass NULL to i2d_X509 so it
	// returns the required buffer length without writing anywhere.
	var scratch *C.uchar
	needed := C.i2d_X509(cert, &scratch)
	if needed <= 0 {
		return nil, fmt.Errorf("i2d_X509: %w", errFromQueue("i2d_X509"))
	}
	if scratch != nil {
		// OpenSSL allocated a buffer with OPENSSL_malloc. Free it to
		// avoid a leak on the size-probe path.
		C.ssl_OPENSSL_free(unsafe.Pointer(scratch))
		scratch = nil
	}

	// Second pass: let OpenSSL allocate, then memcpy into Go.
	written := C.i2d_X509(cert, &scratch)
	if written <= 0 || int(written) != int(needed) {
		if scratch != nil {
			C.ssl_OPENSSL_free(unsafe.Pointer(scratch))
		}
		return nil, fmt.Errorf("i2d_X509 second pass: %w", errFromQueue("i2d_X509"))
	}
	defer C.ssl_OPENSSL_free(unsafe.Pointer(scratch))

	buf := make([]byte, int(written))
	src := unsafe.Slice((*byte)(unsafe.Pointer(scratch)), int(written))
	copy(buf, src)
	return buf, nil
}