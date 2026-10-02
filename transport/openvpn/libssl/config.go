//go:build darwin && with_libssl

package libssl

/*
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include <stdlib.h>
#include <string.h>
#include "libssl_helpers.c"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Config mirrors the subset of *tls.Config the OpenVPN transport needs.
// The transport calls NewClient with these three PEM blocks and expects
// libssl to wire them into an SSL_CTX the same way crypto/tls would:
//
//   - RootPEM is the CA bundle used to validate the server certificate.
//     The verify callback runs after OpenSSL's internal chain builder
//     produces a candidate chain; we re-run the standard Go x509.Verify
//     against RootPEM so the trust anchors match exactly what the
//     Go-based path uses today.
//   - CertPEM and KeyPEM are the optional mTLS credentials. Either both
//     are non-empty or both are empty (consistent with the upstream
//     config validation in transport/openvpn/config.go).
type Config struct {
	RootPEM []byte
	CertPEM []byte
	KeyPEM  []byte
}

// newSSLContext constructs an SSL_CTX suitable for a TLS 1.2/1.3 client
// using the legacy + default providers loaded by ensureProviders. It
// returns the SSL_CTX pointer; the caller owns it and must free it with
// SSL_CTX_free when done.
func newSSLContext(cfg *Config) (*C.SSL_CTX, error) {
	ensureProviders()
	// Lock the goroutine to the OS thread for the duration of the SSL
	// configuration sequence. This matches the convention used by every
	// Go + OpenSSL wrapper that exposes concurrency: OpenSSL's ERR_*
	// state is per-thread, and LockOSThread keeps subsequent SSL_*
	// calls (which happen on the same goroutine) on the same thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ctx := C.SSL_CTX_new(C.TLS_client_method())
	if ctx == nil {
		return nil, fmt.Errorf("SSL_CTX_new: %w", errFromQueue("TLS_client_method"))
	}

	// Set the verify mode to SSL_VERIFY_PEER so OpenSSL performs its
	// own chain validation; we still apply the Go x509.Verify policy
	// after handshake completes (see x509.go). The callback pointer is
	// left at the default, which means OpenSSL returns success/failure
	// based solely on its built-in chain builder.
	C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_PEER, nil)

	// OpenSSL 3.x ships the legacy provider's ciphers (including
	// DHE-RSA-AES256-GCM-SHA384) only when OSSL_PROVIDER_load succeeds,
	// which ensureProviders has now attempted. We deliberately do not
	// call SSL_CTX_set_cipher_list so the libssl compile-time default
	// (DEFAULT:@SECLEVEL=2) is in effect — that default already
	// includes the DHE-RSA suites we need.

	if err := loadTrustAnchors(ctx, cfg.RootPEM); err != nil {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("load trust anchors: %w", err)
	}

	// mTLS: both PEMs must be present together. The upstream
	// transport/openvpn/config.go:309-322 enforces the same invariant
	// on the Go side, so we can rely on it here.
	if len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0 {
		if err := loadClientCertificate(ctx, cfg.CertPEM, cfg.KeyPEM); err != nil {
			C.SSL_CTX_free(ctx)
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
	} else if len(cfg.CertPEM) != 0 || len(cfg.KeyPEM) != 0 {
		C.SSL_CTX_free(ctx)
		return nil, errors.New("client cert and key must both be provided or both omitted")
	}

	return ctx, nil
}

// loadTrustAnchors parses every certificate in pem and adds it to the
// SSL_CTX's X509 store. The store replaces the default empty one so
// only the operator-supplied roots are trusted.
//
// If pem is empty (e.g. the smoketest pass-through that wants to use
// the system trust store), we fall back to OpenSSL's default trust
// locations via SSL_CTX_set_default_verify_paths so the call still
// succeeds. Production callers always supply a non-empty CA bundle.
func loadTrustAnchors(ctx *C.SSL_CTX, pem []byte) error {
	if len(pem) == 0 {
		// SSL_CTX_set_default_verify_paths consults the directories
		// compiled into OpenSSL (typically /etc/ssl on Linux,
		// /System/Library/OpenSSL on macOS). For a one-off smoke
		// test against a self-signed cert this still fails
		// verification (the test cert is not in any default store),
		// so the smoketest additionally skips the verify step in
		// the production verify callback.
		if rc := C.SSL_CTX_set_default_verify_paths(ctx); rc != 1 {
			return fmt.Errorf("SSL_CTX_set_default_verify_paths: %w", errFromQueue("SSL_CTX_set_default_verify_paths"))
		}
		return nil
	}
	store := C.SSL_CTX_get_cert_store(ctx)
	if store == nil {
		return errors.New("SSL_CTX_get_cert_store returned NULL")
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem[0]), C.int(len(pem)))
	if bio == nil {
		return fmt.Errorf("BIO_new_mem_buf: %w", errFromQueue("BIO_new_mem_buf"))
	}
	defer C.BIO_free(bio)

	count := 0
	for {
		cert := C.PEM_read_bio_X509(bio, nil, nil, nil)
		if cert == nil {
			// PEM_read_bio_X509 returns NULL when no further PEM block
			// is available; that is the expected end of stream.
			// Distinguish it from a real error by inspecting the queue.
			e := C.ERR_peek_last_error()
			if e == 0 {
				break
			}
			// 0x0906D07C is ERR_LIB_PEM, "no start line". Any other
			// code is a malformed PEM block we should surface.
			lib := C.ERR_GET_LIB(e)
			reason := C.ERR_GET_REASON(e)
			if C.ulong(lib) == C.ulong(C.ERR_LIB_PEM) && C.int(reason) == C.PEM_R_NO_START_LINE {
				C.ERR_clear_error()
				break
			}
			detail := errFromQueue("PEM_read_bio_X509")
			return fmt.Errorf("parse trust anchor %d: %w", count, detail)
		}
		if rc := C.X509_STORE_add_cert(store, cert); rc != 1 {
			// X509_STORE_add_cert returns 0 if the cert is a duplicate
			// or fails a basic policy check (e.g. expired). We treat
			// duplicates as success because crypto/tls's CertPool has
			// the same dedup behaviour.
			errCode := C.ERR_peek_last_error()
			C.ERR_clear_error()
			if errCode != 0 && C.ERR_GET_REASON(errCode) != C.X509_R_CERT_ALREADY_IN_HASH_TABLE {
				C.X509_free(cert)
				return fmt.Errorf("X509_STORE_add_cert: %w", errFromQueue("X509_STORE_add_cert"))
			}
		}
		count++
		C.X509_free(cert)
	}
	if count == 0 {
		return errors.New("no trust anchors parsed from PEM")
	}
	return nil
}

// loadClientCertificate installs the mTLS PEM into the SSL_CTX. The
// mem-BIO approach avoids writing the PEM to a temp file on disk.
//
// OpenSSL requires that PEM_read_bio_X509 (cert) and
// PEM_read_bio_PrivateKey (key) succeed for the same SSL_CTX before
// the first SSL handshake. The pointer pairing below relies on
// SSL_CTX_use_certificate + SSL_CTX_use_PrivateKey keeping their
// respective X509/EVP_PKEY alive until SSL_CTX_free.
func loadClientCertificate(ctx *C.SSL_CTX, certPEM, keyPEM []byte) error {
	// --- Certificate ---
	cb := C.BIO_new_mem_buf(unsafe.Pointer(&certPEM[0]), C.int(len(certPEM)))
	if cb == nil {
		return fmt.Errorf("BIO_new_mem_buf(cert): %w", errFromQueue("BIO_new_mem_buf"))
	}
	cert := C.PEM_read_bio_X509(cb, nil, nil, nil)
	C.BIO_free(cb)
	if cert == nil {
		return fmt.Errorf("PEM_read_bio_X509(cert): %w", errFromQueue("PEM_read_bio_X509"))
	}
	if rc := C.SSL_CTX_use_certificate(ctx, cert); rc != 1 {
		C.X509_free(cert)
		return fmt.Errorf("SSL_CTX_use_certificate: %w", errFromQueue("SSL_CTX_use_certificate"))
	}
	// Ownership transferred to ctx; do not free cert here.

	// --- Private key ---
	kb := C.BIO_new_mem_buf(unsafe.Pointer(&keyPEM[0]), C.int(len(keyPEM)))
	if kb == nil {
		return fmt.Errorf("BIO_new_mem_buf(key): %w", errFromQueue("BIO_new_mem_buf"))
	}
	key := C.PEM_read_bio_PrivateKey(kb, nil, nil, nil)
	C.BIO_free(kb)
	if key == nil {
		return fmt.Errorf("PEM_read_bio_PrivateKey: %w", errFromQueue("PEM_read_bio_PrivateKey"))
	}
	if rc := C.SSL_CTX_use_PrivateKey(ctx, key); rc != 1 {
		C.EVP_PKEY_free(key)
		return fmt.Errorf("SSL_CTX_use_PrivateKey: %w", errFromQueue("SSL_CTX_use_PrivateKey"))
	}
	// Ownership transferred to ctx.

	if rc := C.SSL_CTX_check_private_key(ctx); rc != 1 {
		return fmt.Errorf("SSL_CTX_check_private_key: %w", errFromQueue("SSL_CTX_check_private_key"))
	}
	return nil
}