//go:build darwin && with_libssl

package libssl

/*
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include <stdlib.h>
#include <string.h>
#include "libssl_helpers.c"
*/
import "C"

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Conn is the libssl-backed counterpart of *crypto/tls.Conn. It speaks
// the subset of net.Conn the OpenVPN transport requires and exposes
// HandshakeContext to drive the synchronous client handshake.
type Conn struct {
	// ssl is the OpenSSL session handle. The handle is created once and
	// reused for every HandshakeContext invocation. On rekey the
	// caller is expected to drop this Conn and create a fresh one; we
	// intentionally do not call SSL_shutdown so that dropping matches
	// crypto/tls's "no close_notify" semantics the OpenVPN transport
	// relies on (see transport/openvpn/client.go:243-247).
	ssl *C.SSL

	// bioIn / bioOut are the read/write memory BIOs attached to ssl.
	// bioIn is fed by reading bytes from transport; bioOut is drained
	// to transport on every pump cycle.
	bioIn  *C.BIO
	bioOut *C.BIO

	// transport is the underlying net.Conn (typically a *ControlConn
	// inside transport/openvpn). It owns no SSL state; we only call
	// Read/Write/SetDeadline on it.
	transport net.Conn

	// closed flips to 1 the first time Close is called. SSL resources
	// are released exactly once.
	closed atomic.Bool

	// closeMu serialises the SSL_free / BIO_free sequence. SSL_free
	// itself is not goroutine-safe and must not race with itself.
	closeMu sync.Mutex
}

// NewClient creates a libssl client Conn that drives TLS over
// transport. The caller transfers ownership of transport: any future
// SetReadDeadline/SetWriteDeadline calls on this Conn will delegate to
// transport. NewClient does not perform the handshake — call
// HandshakeContext for that.
func NewClient(transport net.Conn, cfg *Config) (*Conn, error) {
	if transport == nil {
		return nil, errors.New("libssl: nil transport")
	}
	if cfg == nil {
		return nil, errors.New("libssl: nil config")
	}

	ctx, err := newSSLContext(cfg)
	if err != nil {
		return nil, err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ssl := C.SSL_new(ctx)
	if ssl == nil {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("SSL_new: %w", errFromQueue("SSL_new"))
	}
	// Ownership of ctx transfers to ssl: SSL_free will free the ctx
	// too. We must not call SSL_CTX_free after this point.

	bioIn := C.BIO_new(C.BIO_s_mem())
	if bioIn == nil {
		C.SSL_free(ssl)
		return nil, fmt.Errorf("BIO_new(BIO_s_mem) read: %w", errFromQueue("BIO_new"))
	}
	bioOut := C.BIO_new(C.BIO_s_mem())
	if bioOut == nil {
		C.BIO_free(bioIn)
		C.SSL_free(ssl)
		return nil, fmt.Errorf("BIO_new(BIO_s_mem) write: %w", errFromQueue("BIO_new"))
	}
	C.SSL_set_bio(ssl, bioIn, bioOut)
	// OpenSSL retains BIOs via SSL_set_bio; SSL_free will free them.

	return &Conn{
		ssl:       ssl,
		bioIn:     bioIn,
		bioOut:    bioOut,
		transport: transport,
	}, nil
}

// HandshakeContext drives SSL_connect to completion, pumping bytes
// between the in/out memory BIOs and the underlying transport as the
// handshake progresses.
//
// Cancellation: the caller is expected to install an
// `interruptControlConnOnDone` style callback on ctx (the OpenVPN
// transport already does this for every epoch). When ctx fires, the
// transport's Read returns net.ErrClosed, which we propagate.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Bound the handshake on the application side too. The OpenVPN
	// transport installs a renegotiateTimeout of 30s; mirror that
	// here so a server that stalls on the cert chain does not block
	// forever. We still respect ctx if it has a shorter deadline.
	deadline, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	for {
		if err := deadline.Err(); err != nil {
			return err
		}
		// Lock for the whole pump-and-connect iteration. OpenSSL's
		// ERR state is per-thread; SSL_connect + BIO_read +
		// SSL_get_error all need to run on the same OS thread so the
		// error queue stays consistent with the return value we read.
		runtime.LockOSThread()
		rv := C.SSL_connect(c.ssl)
		errCode := C.SSL_get_error(c.ssl, rv)
		if rv == 1 {
			runtime.UnlockOSThread()
			return nil
		}

		var transportErr error
		switch int(errCode) {
		case wantRead, wantWrite:
			// Always drain the outbound BIO first so the server gets
			// whatever OpenSSL has produced so far (e.g. the
			// ClientHello on the first WANT_READ).
			if e := c.flushOutLocked(); e != nil {
				transportErr = e
				break
			}
			if int(errCode) == wantRead {
				if e := c.fillInLocked(); e != nil {
					transportErr = e
				}
			}
		default:
			transportErr = sslError("SSL_connect", errCode)
		}
		runtime.UnlockOSThread()

		if transportErr != nil {
			if isTemporaryNetError(transportErr) && deadline.Err() == nil {
				// The transport's Read returned a timeout. The server
				// may still respond shortly; retry until the deadline
				// is hit. SSL_connect will return WANT_READ again.
				continue
			}
			return transportErr
		}
	}
}

// PeerCertificates returns the parsed server certificate chain as
// []*x509.Certificate. The transport calls this once after a successful
// HandshakeContext and runs the same x509.Verify policy that
// crypto/tls's VerifyConnection would have used.
func (c *Conn) PeerCertificates() ([]*x509.Certificate, error) {
	return peerCertificates(c.ssl)
}

// Read returns decrypted bytes from the TLS session. The transport
// passes the same set as TLS Handshake timeouts / push-read timeouts
// via SetReadDeadline on the underlying transport (SetDeadline here
// delegates to that).
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		// Always drain whatever OpenSSL has queued to the wire before
		// pulling more ciphertext in. Otherwise a one-direction
		// socket could stall when OpenSSL wants to emit a record
		// (alert, renegotiation HelloRequest) before consuming
		// application data.
		runtime.LockOSThread()
		if err := c.flushOutLocked(); err != nil {
			runtime.UnlockOSThread()
			return 0, err
		}
		rv := C.SSL_read(c.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
		if rv > 0 {
			runtime.UnlockOSThread()
			return int(rv), nil
		}
		errCode := C.SSL_get_error(c.ssl, rv)
		var transportErr error
		switch int(errCode) {
		case wantRead:
			if e := c.fillInLocked(); e != nil {
				transportErr = e
			}
		case wantWrite:
			// Want-write on a read path means OpenSSL wants to emit
			// data; we already flushed above so loop.
		default:
			transportErr = sslError("SSL_read", errCode)
		}
		runtime.UnlockOSThread()

		if transportErr != nil {
			if errors.Is(transportErr, io.EOF) {
				return 0, io.EOF
			}
			if isTemporaryNetError(transportErr) {
				// Timeout from transport: the OpenVPN transport's
				// readTokenPushReply treats net.Error{Timeout:true}
				// as a non-fatal condition that preserves leftover
				// bytes; we mirror that.
				return 0, transportErr
			}
			return 0, transportErr
		}
	}
}

// Write encrypts the supplied plaintext and pushes the resulting
// ciphertext to transport. It returns the number of plaintext bytes
// consumed (matching io.Writer).
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(b) {
		runtime.LockOSThread()
		rv := C.SSL_write(c.ssl, unsafe.Pointer(&b[written]), C.int(len(b)-written))
		errCode := C.SSL_get_error(c.ssl, rv)
		var transportErr error
		if rv > 0 {
			written += int(rv)
			transportErr = c.flushOutLocked()
			runtime.UnlockOSThread()
			if transportErr != nil {
				return written, transportErr
			}
			continue
		}
		switch int(errCode) {
		case wantRead:
			if e := c.fillInLocked(); e != nil {
				transportErr = e
			}
		case wantWrite:
			// OpenSSL wants us to flush before more data; we already
			// flushed above (and at the top of each iteration).
		default:
			transportErr = sslError("SSL_write", errCode)
		}
		runtime.UnlockOSThread()

		if transportErr != nil {
			return written, transportErr
		}
	}
	return written, nil
}

// Close releases the SSL session, the BIO pair, and the underlying
// transport. It deliberately does NOT call SSL_shutdown: the OpenVPN
// transport drops epochs without graceful TLS alerts (see client.go:243).
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	var firstErr error
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if c.ssl != nil {
		// SSL_free will free bioIn/bioOut attached via SSL_set_bio and
		// the underlying SSL_CTX. We must not double-free.
		C.SSL_free(c.ssl)
		c.ssl = nil
		c.bioIn = nil
		c.bioOut = nil
	}
	if c.transport != nil {
		if e := c.transport.Close(); e != nil && firstErr == nil {
			firstErr = e
		}
		c.transport = nil
	}
	return firstErr
}

// SetDeadline delegates to the underlying transport. The OpenVPN
// transport uses this to enforce AUTH_PENDING / continuation windows
// during push-reply reads.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.transport.SetDeadline(t)
}

// SetReadDeadline delegates to the underlying transport.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.transport.SetReadDeadline(t)
}

// SetWriteDeadline delegates to the underlying transport.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.transport.SetWriteDeadline(t)
}

// flushOutLocked moves every byte currently pending in the outbound BIO
// to the underlying transport. Caller must hold the OS thread lock.
func (c *Conn) flushOutLocked() error {
	if c.bioOut == nil || c.transport == nil {
		return nil
	}
	var buf [16384]byte
	for {
		n := int(C.ssl_bio_drain_pending(c.bioOut, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf))))
		if n <= 0 {
			return nil
		}
		if _, err := c.transport.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// fillInLocked pulls one chunk of ciphertext from the underlying
// transport into the inbound BIO. Caller must hold the OS thread lock.
//
// We do not loop here because we want SSL_connect / SSL_read to drive
// the iteration. fillInLocked only ever needs to deliver enough bytes
// to satisfy one WANT_READ.
func (c *Conn) fillInLocked() error {
	if c.bioIn == nil || c.transport == nil {
		return io.EOF
	}
	var buf [16384]byte
	n, err := c.transport.Read(buf[:])
	if err != nil {
		return err
	}
	if n == 0 {
		return io.EOF
	}
	written := int(C.BIO_write(c.bioIn, unsafe.Pointer(&buf[0]), C.int(n)))
	if written != n {
		return fmt.Errorf("BIO_write short: wrote %d, expected %d", written, n)
	}
	return nil
}

// wantRead / wantWrite mirror the SSL_ERROR_* constants. We compare by
// integer value rather than cgo symbol because cgo does not let us
// import non-function symbols cheaply.
const (
	wantRead  = 2
	wantWrite = 3
)

// isTemporaryNetError reports whether err looks like a transport-level
// timeout that the transport should retry (instead of failing the
// handshake / read). net.Error's Timeout() is true for both deadlines
// and explicit context cancellations triggered via
// interruptControlConnOnDone.
func isTemporaryNetError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}