//go:build darwin && with_libssl

// libssl is the cgo + libssl replacement for crypto/tls used by the
// OpenVPN transport. It exposes a Conn whose surface (Read, Write,
// Close, HandshakeContext, SetDeadline, SetReadDeadline,
// SetWriteDeadline) is exactly what transport/openvpn requires from
// *crypto/tls.Conn. The package is built only when:
//
//   1. The operator builds with -tags with_libssl.
//   2. CGO_ENABLED=1 (cgo is needed to talk to libssl).
//   3. GOOS is darwin (this iteration targets macOS only; Linux/Windows
//      can be added by extending the build tag and the Makefile targets
//      later).
//
// All other builds use stub.go, an equally-complete but error-only
// surface, so the upstream CGO_ENABLED=0 build is unchanged.
package libssl

/*
#cgo pkg-config: openssl
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include "libssl_helpers.c"
*/
import "C"

import (
	"sync"
	"unsafe"
)

// providerOnce ensures the OpenSSL 3 legacy + default providers are
// loaded exactly once across all Conn instances. The legacy provider
// re-enables the DHE-RSA cipher suites that the OpenVPN server expects
// but that OpenSSL 3's default provider does not advertise.
var providerOnce sync.Once

// ensureProviders loads the OpenSSL 3 legacy and default providers. The
// legacy provider is required for ciphers such as
// TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f) that the OpenVPN server
// selects when the underlying cipher negotiation has been narrowed
// from the default TLS 1.3-only set. The default provider is loaded
// explicitly so we never depend on openssl.cnf for first-party
// ciphers.
func ensureProviders() {
	providerOnce.Do(func() {
		// Best-effort: errors here are non-fatal because older OpenSSL
		// 3.x builds already ship DHE-RSA in the default provider.
		// The legacy provider adds coverage for very old suites that
		// some 2.x servers might still emit.
		_ = loadProvider("legacy")
		_ = loadProvider("default")
	})
}

// loadProvider asks OpenSSL to load a named provider. It returns nil on
// success and a non-nil error on failure (caller may choose to ignore
// the error because the provider might already be loaded by another
// component of the host process).
func loadProvider(name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	prov := C.OSSL_PROVIDER_load(nil, cName)
	if prov == nil {
		// Drain OpenSSL's error queue so it does not leak into a later
		// SSL_* call.
		C.ERR_clear_error()
		return errFromQueue("OSSL_PROVIDER_load")
	}
	return nil
}

// errFromQueue formats the most recent OpenSSL error (if any) into a
// human-readable string. Returns nil if the queue is empty.
func errFromQueue(prefix string) error {
	var buf [256]C.char
	e := C.ERR_get_error()
	if e == 0 {
		return nil
	}
	C.ERR_error_string_n(C.ulong(e), &buf[0], 256)
	return &GenericError{prefix: prefix, detail: C.GoString(&buf[0])}
}

// GenericError wraps the message returned by ERR_error_string_n.
type GenericError struct {
	prefix string
	detail string
}

func (e *GenericError) Error() string {
	if e.detail == "" {
		return e.prefix
	}
	return e.prefix + ": " + e.detail
}

// errSSL wraps an SSL_get_error code. It carries the symbolic name for
// easier debugging in production logs.
type errSSL struct {
	code    C.int
	details string
}

func (e *errSSL) Error() string {
	return e.details
}

// sslErrorString returns a human-readable name for an SSL_get_error
// code. OpenSSL's header defines these constants, but the project does
// not import the cgo numeric constants directly to avoid drift; we map
// them here.
func sslErrorString(code C.int) string {
	switch int(code) {
	case 0:
		return "SSL_ERROR_NONE"
	case 1:
		return "SSL_ERROR_SSL"
	case 2:
		return "SSL_ERROR_WANT_READ"
	case 3:
		return "SSL_ERROR_WANT_WRITE"
	case 4:
		return "SSL_ERROR_WANT_X509_LOOKUP"
	case 5:
		return "SSL_ERROR_SYSCALL"
	case 6:
		return "SSL_ERROR_ZERO_RETURN"
	case 7:
		return "SSL_ERROR_WANT_CONNECT"
	case 8:
		return "SSL_ERROR_WANT_ACCEPT"
	default:
		return "SSL_ERROR_UNKNOWN"
	}
}

// sslError returns an errSSL formatted with the current OpenSSL error
// queue (if any).
func sslError(prefix string, code C.int) error {
	name := sslErrorString(code)
	detail := errFromQueue(prefix)
	if detail != nil {
		return &errSSL{code: code, details: name + ": " + detail.Error()}
	}
	return &errSSL{code: code, details: name}
}

// clearErrorQueue pops and discards every entry currently on the error
// queue. We use this before invoking an SSL_* call whose return value
// is expected to be WANT_* and whose queue entries are not worth
// surfacing (BIO reads when the buffer is empty, for example).
func clearErrorQueue() {
	for {
		if C.ERR_get_error() == 0 {
			return
		}
	}
}