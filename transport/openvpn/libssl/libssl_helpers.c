// SPDX-License-Identifier: Apache-2.0
//
// Helper C functions shared between the .go files in the libssl
// package. Each .go file's cgo preamble `#include`s this file so the
// helpers are available across ssl.go, conn.go, and x509.go without
// the preamble-isolation problem (cgo symbols are file-scoped, not
// package-scoped, so inline static helpers in one preamble are not
// visible from another).

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

// ssl_bio_drain_pending transfers up to `cap` bytes from a memory BIO
// to the caller buffer. Used by the write side of the libssl client: a
// loop in conn.go calls this until it returns 0 to know there is no
// more buffered ciphertext.
static inline int ssl_bio_drain_pending(BIO *bio, unsigned char *buf, int cap) {
    int pending = BIO_ctrl_pending(bio);
    if (pending <= 0) {
        return 0;
    }
    if (pending > cap) {
        pending = cap;
    }
    return (int)BIO_read(bio, buf, pending);
}

// sk_X509_num / sk_X509_value were renamed in OpenSSL 3.x. The new
// names go through OPENSSL_sk_num / OPENSSL_sk_value which take an
// OPENSSL_STACK. The macros OPENSSL_sk_X509_num / OPENSSL_sk_X509_value
// exist in safestack.h but cgo cannot resolve them as identifiers, so
// we wrap them in plain C functions.
static inline int ssl_sk_X509_num(const STACK_OF(X509) *s) {
    return OPENSSL_sk_num((const OPENSSL_STACK *)s);
}

static inline X509 *ssl_sk_X509_value(const STACK_OF(X509) *s, int i) {
    return (X509 *)OPENSSL_sk_value((const OPENSSL_STACK *)s, i);
}

// OPENSSL_free is a macro in OpenSSL 3.x; cgo cannot resolve macro
// expansions as if they were functions, so we wrap it.
static inline void ssl_OPENSSL_free(void *p) {
    OPENSSL_free(p);
}