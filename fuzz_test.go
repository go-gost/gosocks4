package gosocks4

import (
	"bytes"
	"testing"
)

// FuzzAddrDecode parses the 6-byte SOCKS4 address wire format. The input is
// fully attacker-controlled (every byte from a client connection), so a panic
// here is a remote DoS. The fuzzer must never crash; short buffers return
// ErrShortDataLength by contract.
func FuzzAddrDecode(f *testing.F) {
	f.Add([]byte{})                           // empty
	f.Add([]byte{0, 80})                      // 2 bytes < 6
	f.Add([]byte{0, 80, 127, 0, 0, 1})        // IPv4
	f.Add([]byte{0, 53, 0, 0, 0, 42})         // SOCKS4A domain marker
	f.Add([]byte{0xFF, 0xFF, 10, 0, 0, 1})    // max port
	f.Add([]byte{0, 80, 0, 2, 0, 0})          // zero-first-octet, not 4A
	f.Fuzz(func(t *testing.T, b []byte) {
		addr := new(Addr)
		_ = addr.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzReadRequest parses a SOCKS4 request stream. Seeds cover CONNECT, BIND,
// SOCKS4A domain, bad version, bad command, and a short header.
func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{4, 1, 0, 80, 127, 0, 0, 1, 'u', 's', 'e', 'r', 0})
	f.Add([]byte{4, 2, 1, 0xBB, 10, 0, 0, 1, 't', 'e', 's', 't', 0}) // BIND
	f.Add([]byte{4, 1, 0, 53, 0, 0, 0, 1, 'u', 0, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0}) // 4A
	f.Add([]byte{5, 1, 0, 80, 127, 0, 0, 1, 'u', 0}) // bad version
	f.Add([]byte{4, 99, 0, 80, 127, 0, 0, 1, 'u', 0}) // bad command
	f.Add([]byte{4, 1, 0})                             // short header
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadRequest(bytes.NewReader(b))
	})
}

// FuzzReadReply parses a SOCKS4 reply stream.
func FuzzReadReply(f *testing.F) {
	f.Add([]byte{0, 90, 0, 80, 127, 0, 0, 1}) // granted
	f.Add([]byte{0, 91, 0, 0, 0, 0, 0, 0})    // failed
	f.Add([]byte{1, 90, 0, 80, 127, 0, 0, 1}) // bad version
	f.Add([]byte{0, 90})                       // short
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadReply(bytes.NewReader(b))
	})
}
