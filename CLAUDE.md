# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
# Build/lint check (standard Go)
go vet ./...
```

There are no tests in this repository. `go vet` is the primary verification.

## Architecture

A single-file Go library implementing [SOCKS Protocol Version 4](socks4.protocol.txt) and the [SOCKS 4A extension](socks4a.protocol.txt) (domain name support). The module is imported as `github.com/go-gost/gosocks4` by the broader GOST workspace (`x/handler/socks/v4/` and `x/handler/auto/`).

### Key types

- **`Addr`** — SOCKS4 destination address (host type + host string + port). For IPv4 addresses, the 4-byte IP is stored as a string. For SOCKS4A, the type is `AddrDomain` and the hostname is stored as a string, with the 4-byte field encoded as `0.0.0.x` (where x is nonzero) per the 4A spec. `Decode` reads from a 6-byte wire-format slice; `Encode` writes to one.
- **`Request`** — CONNECT or BIND request (command byte + address + userid). `ReadRequest(r io.Reader)` reads from a stream and handles SOCKS4A domain name fallback transparently. `Write(w io.Writer)` writes to a stream.
- **`Reply`** — Server reply (result code + bound address). `ReadReply`/`Write` handle wire format.

### Constants

- Protocol version: `Ver4 = 4`
- Commands: `CmdConnect = 1`, `CmdBind = 2`
- Address types: `AddrIPv4 = 0`, `AddrDomain = 1`
- Reply codes: `Granted = 90`, `Failed = 91`, `Rejected = 92`, `RejectedUserid = 93`
- Field limits: `maxUseridLen = 255`, `maxHostnameLen = 255`

### Wire protocol

The library handles both SOCKS4 (IP-based) and SOCKS4A (domain-based) transparently in `ReadRequest`: if the IP bytes in the request are `0.0.0.x` with non-zero `x`, it reads an additional null-terminated hostname after the userid. `Addr.Type` is set accordingly.

### Sentinel errors

`ErrBadVersion`, `ErrBadAddrType`, `ErrShortDataLength`, `ErrBadCmd`, `ErrFieldTooLong` — returned directly (no wrapping). Callers in `x/handler/socks/v4/` check these with `==`.
