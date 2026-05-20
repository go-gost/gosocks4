# gosocks4

A Go library implementing the SOCKS Protocol Version 4 and the SOCKS 4A extension (domain name support).

## Installation

```bash
go get github.com/go-gost/gosocks4
```

## Usage

### Reading a request (server-side)

```go
import "github.com/go-gost/gosocks4"

func handleConnection(conn net.Conn) {
    req, err := gosocks4.ReadRequest(conn)
    if err != nil {
        // handle error
    }

    if req.Cmd == gosocks4.CmdConnect {
        // Dial the target
        target, _ := net.Dial("tcp", req.Addr.String())

        // Reply granted with the bound address
        reply := gosocks4.NewReply(gosocks4.Granted, &gosocks4.Addr{
            Type: gosocks4.AddrIPv4,
            Host: "0.0.0.0",
            Port: 0,
        })
        reply.Write(conn)

        // Relay traffic
        // ...
    }
}
```

### Writing a request (client-side)

```go
req := gosocks4.NewRequest(gosocks4.CmdConnect, &gosocks4.Addr{
    Type: gosocks4.AddrIPv4,
    Host: "93.184.216.34",
    Port: 80,
}, []byte("userid"))

err := req.Write(conn)
```

### SOCKS 4A (domain names)

```go
req := gosocks4.NewRequest(gosocks4.CmdConnect, &gosocks4.Addr{
    Type: gosocks4.AddrDomain,
    Host: "example.com",
    Port: 443,
}, []byte("userid"))

err := req.Write(conn)
```

### Reading a reply (client-side)

```go
reply, err := gosocks4.ReadReply(conn)
switch reply.Code {
case gosocks4.Granted:
    // Connection granted
case gosocks4.Failed, gosocks4.Rejected:
    // Request rejected
case gosocks4.RejectedUserid:
    // Auth failure
}
```

## Types

### Addr

SOCKS4 destination address.

```go
type Addr struct {
    Type int      // AddrIPv4 or AddrDomain
    Host string   // IPv4 address or hostname
    Port uint16   // Destination port
}
```

Methods: `Decode(b []byte) error`, `Encode(b []byte) error`, `String() string`

### Request

SOCKS4 CONNECT/BIND request.

```go
type Request struct {
    Cmd    uint8   // CmdConnect or CmdBind
    Addr   *Addr   // Destination address
    Userid []byte  // User identifier
}
```

Methods: `ReadRequest(r io.Reader) (*Request, error)`, `Write(w io.Writer) error`, `String() string`

### Reply

SOCKS4 server reply.

```go
type Reply struct {
    Code uint8   // Granted, Failed, Rejected, RejectedUserid
    Addr *Addr   // Bound address
}
```

Methods: `ReadReply(r io.Reader) (*Reply, error)`, `Write(w io.Writer) error`, `String() string`

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `Ver4` | 4 | Protocol version |
| `CmdConnect` | 1 | CONNECT command |
| `CmdBind` | 2 | BIND command |
| `AddrIPv4` | 0 | IPv4 address type |
| `AddrDomain` | 1 | Domain name type (SOCKS 4A) |
| `Granted` | 90 | Request granted |
| `Failed` | 91 | Request rejected or failed |
| `Rejected` | 92 | Request rejected (identd) |
| `RejectedUserid` | 93 | Request rejected (userid mismatch) |

## Wire Format

```
Request:
+----+----+----+----+----+----+----+----+----+----+....+----+
| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
+----+----+----+----+----+----+----+----+----+----+....+----+
   1    1      2              4           variable       1

SOCKS 4A: if DSTIP is 0.0.0.x (x != 0), a null-terminated hostname
follows after the userid:

+----+----+----+----+----+----+----+----+----+....+----+
| HOSTNAME                                          |NULL|
+----+----+----+----+----+----+----+----+----+....+----+
              variable                                 1

Reply:
+----+----+----+----+----+----+----+----+
| VN | CD | DSTPORT |      DSTIP        |
+----+----+----+----+----+----+----+----+
   1    1      2              4
```

## Errors

| Error | Description |
|-------|-------------|
| `ErrBadVersion` | Invalid protocol version byte |
| `ErrBadAddrType` | Unknown address type or malformed IP |
| `ErrShortDataLength` | Input buffer too short |
| `ErrBadCmd` | Unknown command byte |
| `ErrFieldTooLong` | Userid or hostname exceeds 255-byte limit |

## References

- [SOCKS Protocol Version 4](https://www.openssh.com/txt/socks4.protocol)
- [SOCKS 4A Protocol](https://www.openssh.com/txt/socks4a.protocol)
