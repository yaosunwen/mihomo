# mihomo openvpn: cgo + libssl (DHE-RSA) build flow

## Background

Go's `crypto/tls` deliberately omits DHE-RSA cipher suites. The
upstream tracking issue is **`golang/go#7758`** ("crypto/tls: add DHE
support", closed 2017-01-23 as wontfix). The OpenVPN server we tunnel
through (`45.33.95.168:443` via stunnel at `127.0.0.1:2388`) only
selects DHE-RSA ciphers, so the stock mihomo binary's openvpn transport
handshakes fail with:

```
[TCP] dial facebook-via-vpn ... error: make OpenVPN handshake:
      openvpn tls handshake: EOF
```

The investigation is documented in
`docs/openvpn-handshake-investigation.md` — three-way tcpdump
(Stock OpenVPN binary / Python `ssl` probe / mihomo) confirmed that
the wire format itself is correct (Layer 1) and that the only
remaining problem is cipher mismatch (Layer 2). Go `crypto/tls`
silently drops any 0x009f-style cipher we try to add to `tls.Config.CipherSuites`.

## Solution

The `transport/openvpn/libssl/` package plus the build-tag-gated
`tlsconn_cgo.go` / `tlsconn_nocgo.go` dispatch wrap OpenSSL via cgo so
the OpenVPN control channel can negotiate DHE-RSA. The default
`CGO_ENABLED=0` build is preserved; the libssl build is opt-in via
`-tags with_libssl` (the build tag is `darwin && with_libssl` for now).

Cipher list is left empty so libssl's compile-time default applies,
which already includes `DHE-RSA-AES256-GCM-SHA384` and friends.

## Build flow (per release)

Replace `<TAG>` with the official release tag you want to base on
(e.g. `v1.19.32`). Replace `<VERSION>` with a suffix (e.g.
`v1.19.32-libssl`). `<SHA>` is the abbreviated HEAD of `v1.19.32`.

```bash
# 0. Make sure mihomo is running (gives us network access through the
#    proxy for `git fetch`). If mihomo's fake-IP hijacks github.com,
#    stop it temporarily and re-enable after fetching:
#
#        sudo -n launchctl bootout gui/$(id -u)/my.mihomo
#        sudo -n pkill -9 mihomo
#        git fetch origin --tags
#        # ... do the work ...
#        sudo -n launchctl bootstrap gui/$(id -u) \
#            /Users/yaosunwen/bin/mihomo/my.mihomo.plist
#
#    Most of the time `git ls-remote --tags origin` returns nothing
#    because mihomo's DNS hijack turns the answer into 198.18.0.0/16
#    fake-IPs. Stop mihomo for the fetch step.

cd /Users/yaosunwen/mihomo

# 1. Branch off the official tag.
git checkout -b <VERSION>-libssl <TAG>

# 2. Cherry-pick the libssl commit onto the new branch.
#    (One option: rebase the feature branch instead. Either way
#    the libssl commit hash is what we need.)
#
#    The libssl commit lives on `feature/openvpn-libssl` rebased on
#    top of whatever the latest origin/Alpha was at the time. Look
#    up the hash with:
#
#        git log --oneline feature/openvpn-libssl -1
#
#    Then cherry-pick it. v1.x auto-resolves because the openvpn
#    transport code is largely stable across tags.
git cherry-pick <libssl-commit-hash>

# 3. Build the libssl variant. Requires OpenSSL headers on PKG_CONFIG_PATH.
#    macOS Homebrew: brew install openssl@3
PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig \
    make darwin-arm64-libssl

# 4. Rename + deploy. The Makefile target emits
#    `bin/mihomo-darwin-arm64-libssl` (no version); rename it to
#    match the convention in `~/bin/mihomo/` (other binaries there
#    are tagged with their commit SHA or release version).
mv bin/mihomo-darwin-arm64-libssl bin/mihomo-darwin-arm64-<VERSION>-libssl
cp bin/mihomo-darwin-arm64-<VERSION>-libssl \
   /Users/yaosunwen/bin/mihomo/mihomo-darwin-arm64-<VERSION>-libssl

# 5. Flip the symlink so launchd picks the new binary on next start.
cd /Users/yaosunwen/bin/mihomo
ln -sf mihomo-darwin-arm64-<VERSION>-libssl mihomo

# 6. Restart via the ctl.sh helper (or bootout+bootstrap if you want
#    to bypass sudo cache).
/Users/yaosunwen/bin/mihomo/ctl.sh restart

# 7. Verify.
curl --max-time 15 -o /dev/null -s \
    -w 'http=%{http_code} time=%{time_total}\n' \
    https://www.facebook.com/
# Expect: http=200
```

## Rollback

If a libssl build misbehaves, point the symlink at the last known-good
binary (use the same flow the upgrade script uses):

```bash
cd /Users/yaosunwen/bin/mihomo
ln -sf mihomo-darwin-arm64-alpha-<known-good-sha> mihomo
/Users/yaosunwen/bin/mihomo/ctl.sh restart
```

Keep several alpha / release binaries in the directory as
fallback candidates. The directory layout is intentionally a flat
`bin/mihomo/` of `mihomo-darwin-arm64-{alpha-<sha>|v<version>}` files
plus a single `mihomo` symlink that names the active one.

## Verification

Two layers:

1. **Smoke test** (no real server needed): stand up an `openssl
   s_server` that only offers DHE-RSA, then run the smoketest
   against it:

   ```bash
   cd /tmp
   openssl req -x509 -newkey rsa:2048 -nodes \
       -keyout smoketest.key -out smoketest.crt -days 1 \
       -subj '/CN=localhost'
   /opt/homebrew/opt/openssl@3/bin/openssl s_server \
       -accept 14443 -cert smoketest.crt -key smoketest.key \
       -cipher 'DHE-RSA-AES256-GCM-SHA384' -tls1_2 -www &

   cd /Users/yaosunwen/mihomo
   PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig \
       CGO_ENABLED=1 GOOS=darwin go build \
       -tags 'with_libssl' \
       -o /tmp/libssl-smoketest \
       ./transport/openvpn/libssl/cmd/smoketest

   /tmp/libssl-smoketest
   # Expect: cipher / cert[0] / cert[1] / server reply: ...
   ```

   The smoketest is in `transport/openvpn/libssl/cmd/smoketest/`.

2. **End-to-end**: with the symlink flipped and mihomo restarted,
   `curl https://www.facebook.com/` should return HTTP 200 within
   ~10 s and route through `facebook-via-vpn[openvpn-2388]` per the
   mihomo log.

## Gotchas

- **Build tag is `darwin && with_libssl`**: the cgo path is darwin-only
  for now. linux/windows need additional porting (the helper
  `libssl_helpers.c` is portable as-is; only the `.go` preamble tags
  need to broaden).
- **OpenSSL 3.x only**: uses `TLS_client_method`, `OSSL_PROVIDER_load`,
  `OPENSSL_sk_X509_*`, `OPENSSL_free`. The libssl package init() calls
  `OSSL_PROVIDER_load("legacy")` + `OSSL_PROVIDER_load("default")` to
  make sure DHE-RSA-AES256-GCM-SHA384 is available on a fresh install.
- **Runtime dylib**: the resulting binary dynamically links
  `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib` and `libcrypto.3.dylib`.
  These must be reachable at runtime; Homebrew's dynamic loader
  config handles this on macOS.
- **GitHub SSH over mihomo**: mihomo's DNS hijack returns fake-IPs
  for `github.com`, so SSH-based git operations fail. Either stop
  mihomo for the fetch step or add a `github.com` DIRECT rule.
- **CGO_ENABLED**: must be `1` for the libssl build. The default
  `make` target stays at `CGO_ENABLED=0`; only `make
  darwin-arm64-libssl` flips it on (via the `CGO_BUILD` variable in
  `Makefile`).
- **Rekey safe-drop is intentional**: `libssl.Conn.Close()` does NOT
  call `SSL_shutdown`, mirroring `crypto/tls.Conn` semantics the
  transport relies on (see `transport/openvpn/client.go:243-247`
  comment). Never add `SSL_shutdown` in Close.

## Files

| Path | Role |
|------|------|
| `transport/openvpn/libssl/ssl.go` | cgo preamble, OpenSSL provider bootstrap, error helpers |
| `transport/openvpn/libssl/config.go` | PEM → SSL_CTX: trust anchors, optional mTLS cert/key |
| `transport/openvpn/libssl/x509.go` | `SSL_get_peer_cert_chain` → `[]*x509.Certificate` |
| `transport/openvpn/libssl/conn.go` | `Conn` + `HandshakeContext` + Read/Write/deadline (BIO_s_mem pump) |
| `transport/openvpn/libssl/stub.go` | no-libssl fallback (build tag `!darwin || !with_libssl`) |
| `transport/openvpn/libssl/libssl_helpers.c` | cross-`.go` shared C helpers (sk_X509, OPENSSL_free wrap) |
| `transport/openvpn/libssl/cmd/smoketest/main.go` | round-trip probe vs `openssl s_server` |
| `transport/openvpn/tlsconn.go` | `tlsiConn` interface + `tlsEpoch` wrapper |
| `transport/openvpn/tlsconn_nocgo.go` | default build: `*crypto/tls.Conn` |
| `transport/openvpn/tlsconn_cgo.go` | libssl build: `*libssl.Conn` + post-handshake verify |
| `transport/openvpn/client.go` | `atomic.Pointer[tlsEpoch]` + dispatch |
| `Makefile` | adds `darwin-arm64-libssl` target (CGO_ENABLED=1) |
| `docs/openvpn-handshake-investigation.md` | original cipher-mismatch diagnosis (3-way tcpdump) |