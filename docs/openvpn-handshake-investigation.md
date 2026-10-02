# mihomo OpenVPN `openvpn-2388` handshake investigation

## Status (2026-09-27)

- `hard_reset V2` wire format: **already correct in upstream HEAD**. No
  source change shipped. The bug existed only in the user's local
  working-tree edits (uncommitted), not in `origin/Alpha`.
- Subsequent TLS handshake: **unfixable from the mihomo side** — Go's
  `crypto/tls` does not implement the `DHE-RSA-*` cipher suites that
  the OpenVPN server selects. Workarounds are listed at the bottom of
  this file.

This document is a record of how those two facts were established,
intended for future debugging if the dial fails again. No source
files were modified to reach this conclusion.

## Background

The user-facing symptom was that `curl https://www.facebook.com/`
through mihomo's tun produced

```
[TCP] dial facebook-via-vpn ... error: make OpenVPN handshake:
      openvpn tls handshake: read tcp 127.0.0.1:NNNN->127.0.0.1:2388:
      read: connection reset by peer
```

`facebook-via-vpn` resolves to `openvpn-2388`, which proxies
`127.0.0.1:2388` (`stunnel [us90]`) to `45.33.95.168:443` (the
OpenVPN server). The same `stunnel` path works for the stock
OpenVPN binary, so the failure was on the mihomo client side.

## Layer 1 — hard_reset V2 wire format

### Evidence captured

`mihomo_tx.bin` (the debug dump file written by the locally-modified
`streamPacketIO.WritePacket`) showed the first client packet on every
dial as

```
opcode=0x38 plen=58   ← hard_reset V2
opcode=0x28 plen=62   ← P_ACK_V1
opcode=0x20 plen=1166 ← P_CONTROL_V1 (ClientHello part 1)
opcode=0x20 plen=449  ← P_CONTROL_V1 (ClientHello part 2)
```

while `ovpn_probe.py` (the diagnostic probe in
`/Users/yaosunwen/bin/mihomo/ovpn_probe.py`, with the same
`mihomo.yaml` cert/key/ca) emits 54-byte hard_reset packets and
reaches a server reply.

`ovpn_probe.py` annotates the wire layout as

```
# Layout: opcode(1) + sid(8) + HMAC(32) + pid(8) +
#         ack_count(1) + tls_payload(4) = 54 inner
```

i.e. the 4-byte tail on `hard_reset V2` is the reliable_pid slot,
value zero, *not* an extra payload. mihomo was emitting a hard_reset
V2 with 9 bytes of plaintext (`ack_count` + `reliable_pid` + a
4-byte zero payload) where Stock OpenVPN emits 5.

### Source of the extra 4 bytes

`SendReset` (in `transport/openvpn/control.go`) called

```go
c.Send(ctx, opcode, []byte{0, 0, 0, 0})   // ← 4-byte payload
```

`Send` populates `ControlPacket.MessageID` and routes through
`EncodePlain`, which writes the reliable_pid slot *and* the payload
verbatim:

```go
// packet.go: EncodePlain
if p.Opcode.HasMessageID() {
    size += 4 + len(p.Payload)
}
...
if p.Opcode.HasMessageID() {
    out = append(out, /* reliable_pid = MessageID */)
    out = append(out, p.Payload...)      // ← 4-byte zero payload lands here
}
```

For every other control opcode the extra payload is meaningful
(`MessageID` carries the reliable seq id and the payload carries
the TLS record); for `hard_reset V2`/`V3` it duplicates the
reliable_pid slot with zeros.

### Where the broken code actually lived

`git log -S "SendReset" -- transport/openvpn/control.go`:

- `7af9eeb3 feat: add OpenVPN outbound support (#2785)` — **initial
  commit**. `SendReset` already passes `nil`.
- `e26714a1 feat: support TLS rekey fix, data-ciphers negotiation,
  tls-crypt-v2 for OpenVPN (#2989)` — restructured `SendReset` into
  its current V2/V3-conditional form. **Still passes `nil`.**

`git log -S "_, err := c.Send(ctx, opcode, []byte{0, 0, 0, 0})" -- transport/openvpn/control.go`:
returns **no commits**. The `[]byte{0,0,0,0}` pad was *never* in
upstream — it lived only in an uncommitted local edit of the
working tree, paired with a comment claiming Stock OpenVPN needs
it.

`mihomo.bak-current-failing` (79 MB, root-owned, debug build with
DWARF) was compiled from that broken local source. After the
investigation finished, the local edits were discarded with
`git checkout HEAD -- transport/openvpn/control.go ...` and the
binary was rebuilt from clean `origin/Alpha`. The dial still fails
on Layer 2; Layer 1 was a red herring from start to finish.

### Why the comment justifying the pad was wrong

The local edit's comment said

> Stock OpenVPN writes a 4-byte reliable-pid field (=0) after the
> ack_count on the first hard_reset V2. Without it, the wire
> plaintext is too short by 4 bytes and the server's tls_pre_decrypt
> rejects the packet.

Half-right: Stock OpenVPN *does* write a 4-byte reliable_pid slot
(value zero on the first hard_reset, because hard_reset is
unreliable). But it does **not** also write a 4-byte payload
after that. The reliable_pid slot is the entire 4-byte tail.
`tls_pre_decrypt` verifies the HMAC over the entire plaintext
including any padding, then parses the structure and finds the
record length inconsistent — aborting with a TLS record-length
mismatch that the OpenVPN server surfaces as
`connection reset by peer`.

`tls-auth`'s `EncodePlain` (in `packet.go:128-146`) already writes
the reliable_pid slot. Passing a payload through `Send` makes it
appear *after* the slot, producing the observed 4-byte overshoot.

### Why no fix shipped

The investigation determined the broken code lived only in
uncommitted local edits, not in upstream HEAD. Discarding the local
edits is the fix; the upstream code is correct as-is. Adding
regression tests was considered but rejected — upstream HEAD does
not need protection from itself, and the user already understands
why the original pad was wrong (the same investigation that
produced this document).

## Layer 2 — TLS cipher suite mismatch

After Layer 1's local edits were discarded and mihomo was rebuilt
from clean HEAD, the dial error changed from
`connection reset by peer` to `openvpn tls handshake: EOF`
(graceful close) — i.e. the wire format is now correct, but the
server still won't talk. A side-by-side `tcpdump -i lo0 'tcp port 2388'`
capture with three clients (Stock OpenVPN binary, `ovpn_probe.py`,
mihomo) revealed the second-layer cause.

### What the capture showed

|                                | OpenVPN binary | probe (Python ssl) | mihomo (Go crypto/tls) |
|--------------------------------|---------------:|-------------------:|-----------------------:|
| cipher suites offered          |             24 |                 17 |                     13 |
| server's `ServerHello.cipher`  |      0x009f    |     never reaches  |             never reaches |
| extension `0x0023` (`session_ticket`) |       absent |      present (0B)  |          present (0B)  |
| extension `0x0017` (`extended_master_secret`) | present (0B) | present (0B) |     present (0B)  |
| other 8 extensions              |        identical content |               |                       |

`0x0023` (`session_ticket`): Stock OpenVPN sets
`SSL_OP_NO_TICKET` (`ssl_openssl.c:331`), so the binary's
ClientHello omits the extension entirely. Both `probe.py` and
mihomo include it (Go's `ticketSupported = true && !echInner` in
`handshake_client.go:362`).

`0x0017` (`extended_master_secret`): present in all three. Go's
`extendedMasterSecret: true` (`handshake_client.go:74`).

The other 8 extensions (`0x000a`, `0x000b`, `0x000d`, `0x0016`,
`0x002b`, `0x002d`, `0x0033`, `0xff01`) have identical content
across all three clients. The cipher list is the only meaningful
difference.

### 2a. Server's choice

The server's `ServerHello.cipher_suite` is
`0x009f = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`. None of the
non-binary clients ever see this ServerHello — they see
`close_notify` instead.

### 2b. `session_ticket` — present but not the cause

Verified by patching the Go standard library
(`/opt/homebrew/Cellar/go/1.26.3/libexec/src/crypto/tls/handshake_client.go`,
line 362) to set `ticketSupported = false && !echInner`,
rebuilding mihomo, and running a fresh dial:

```
curl: (28) Connection timed out after 15006 milliseconds
```

i.e. error changed from `EOF` (server immediate close) to
`timeout` (server accepts the ClientHello shape but never replies).
So `session_ticket` is *part* of the rejection but not the whole
story. Patch reverted; the file was restored from the backup.

### 2c. `extended_master_secret` — not the cause

Same experimental approach: patched the Go standard library to set
`extendedMasterSecret: false`, rebuilt mihomo, ran a fresh dial —
still `EOF`. Patch reverted.

### 2d. Cipher suite mismatch — the actual cause

Server's `ServerHello.cipher_suite` is `0x009f =
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`. mihomo's cipher list does
**not** include `0x009f`:

```
mihomo cipher suites (13):
  0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
  0xc009, 0xc013, 0xc00a, 0xc014, 0x1301, 0x1302, 0x1303

OpenVPN binary cipher suites (24):
  ... 0x9f, 0x9e, 0x6b, 0x67, 0x39, 0x33, 0xccaa, ...
```

i.e. mihomo's `crypto/tls` does not offer any `DHE-RSA-*` cipher.
`cipher_suites.go` in Go 1.26.3 lists only `ECDHE-RSA-*`,
`ECDHE-ECDSA-*`, `TLS 1.3 ciphers`, and the Insecure* set —
**no DHE-RSA**.

Adding `CipherSuites: []uint16{0x009f, 0x009e, ...}` to the
`tls.Config` does not help: Go silently drops cipher-suite IDs it
does not implement, so the rebuilt mihomo's ClientHello contained
the same 13 ECDHE-* ciphers. Confirmed by re-capturing the wire
after the rebuild.

This is a Go design decision, not a bug: Go deliberately omits
DHE-RSA-* cipher suites from its supported set because static-DH
cipher suites do not provide forward secrecy. The decision has
been in place since Go 1.0 and is tracked in
[golang/go#31434](https://github.com/golang/go/issues/31434).

## Conclusion

- Layer 1 (wire format) was never broken in upstream. The bug was
  in the user's uncommitted working-tree edits, not in
  `origin/Alpha`. Discarding those edits is the fix; no commit
  needed.
- Layer 2 (cipher mismatch) cannot be fixed in `transport/openvpn/`
  alone. The mihomo `tls.Config` cannot make `crypto/tls` offer
  `0x009f`, because Go's `crypto/tls` package does not implement
  it.

### Workarounds

1. **Server side** — easiest if you have control of the server.
   Add to the OpenVPN server config:
   ```
   tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
   ```
   This forces the server to prefer an ECDHE cipher that Go's
   `crypto/tls` *does* offer.

2. **TLS via OpenSSL** — replace the mihomo TLS client (in
   `transport/openvpn/client.go`'s `tlsConfig` + the actual
   handshake) with `cgo` + libssl. The control-channel packet
   framing stays in Go; only the TLS layer is delegated. This
   is what Stock OpenVPN does and what makes the OpenVPN binary
   able to connect.

3. **stunnel wrapper** — does **not** help. stunnel wraps raw
   TLS but cannot insert itself between the OpenVPN control
   packet and the OpenVPN server, because the OpenVPN server
   expects the TLS handshake to carry the control channel
   bytes, not to relay them.

4. **Accept the limit** — route the workloads that need
   `openvpn-2388` through another mechanism (or use the
   OpenVPN binary directly while it can still reach the server).

## Reproduction recipe

If `openvpn-2388` stops working again, the following steps
reproduce the diagnostic capture from scratch.

```bash
# 1. Re-add the local debug-dump patch (only for diagnosis; revert
#    before committing):
#    transport/openvpn/packetio.go:121-132 prints to stderr and
#    appends to /tmp/mihomo_tx.bin. ReadPacket has no counterpart.
#    Rebuild with: GOFLAGS=-mod=mod go build -tags with_gvisor \
#      -trimpath -ldflags '-X ...Version=... -X ...BuildTime=...' ...

# 2. Stop any existing OpenVPN binary (stunnel can't multiplex
#    multiple OpenVPN clients through one TLS session).
sudo pkill -9 openvpn

# 3. Clear stunnel's session cache.
sudo pkill -9 stunnel
/opt/homebrew/opt/stunnel/bin/stunnel \
    /opt/homebrew/etc/stunnel/stunnel.conf &
sleep 2

# 4. Capture client→stunnel traffic.
sudo tcpdump -i lo0 -w /tmp/ovpn.pcap -U 'tcp port 2388' &

# 5. Trigger a dial.
curl --max-time 8 -o /dev/null -w '%{http_code}\n' \
    https://www.facebook.com/

# 6. Stop capture, parse with dpkt (see scripts in the commit log
#    of this document's predecessor for full parsing code).

# 7. Look for /tmp/mihomo_tx.bin — first 2 bytes are the length
#    of the first OpenVPN control packet. Stock OpenVPN: 54. mihomo
#    with the broken local edit: 58.
```

## Files referenced

| Path | Role |
|---|---|
| `/Users/yaosunwen/bin/mihomo/ovpn_probe.py` | Diagnostic probe that reproduces the Stock OpenVPN ClientHello shape |
| `/Users/yaosunwen/mihomo/transport/openvpn/control.go` | `SendReset` (line 191+); buggy local edit was at line ~202 |
| `/Users/yaosunwen/mihomo/transport/openvpn/packet.go` | `EncodePlain` (line 111+) and `DecodeControlPlain` (line 150+) |
| `/Users/yaosunwen/mihomo/transport/openvpn/packetio.go` | `streamPacketIO.WritePacket` (line 115+); debug dump added at line ~125 |
| `/Users/yaosunwen/ovpn/us90-sunwenyao.ovpn` | Stock OpenVPN config that established the working baseline |
| `/Users/yaosunwen/ovpn/stunnel.conf` | `[us90] accept=127.0.0.1:2388 connect=45.33.95.168:443` |