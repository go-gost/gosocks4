package gosocks4

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// ---- Addr.Decode -----------------------------------------------------------

func TestAddrDecode_IPv4(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80, 127, 0, 0, 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Type != AddrIPv4 {
		t.Errorf("expected type %d, got %d", AddrIPv4, addr.Type)
	}
	if addr.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", addr.Host)
	}
	if addr.Port != 80 {
		t.Errorf("expected port 80, got %d", addr.Port)
	}
}

func TestAddrDecode_ZeroIP(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// b[5] == 0, so NOT SOCKS4A — stays AddrIPv4
	if addr.Type != AddrIPv4 {
		t.Errorf("expected type %d, got %d", AddrIPv4, addr.Type)
	}
	if addr.Host != "0.0.0.0" {
		t.Errorf("expected host 0.0.0.0, got %s", addr.Host)
	}
	if addr.Port != 80 {
		t.Errorf("expected port 80, got %d", addr.Port)
	}
}

func TestAddrDecode_SOCKS4A(t *testing.T) {
	// 0.0.0.x where x != 0 → AddrDomain
	addr := &Addr{}
	err := addr.Decode([]byte{0, 53, 0, 0, 0, 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Type != AddrDomain {
		t.Errorf("expected type %d, got %d", AddrDomain, addr.Type)
	}
	if addr.Port != 53 {
		t.Errorf("expected port 53, got %d", addr.Port)
	}
}

func TestAddrDecode_MaxPort(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{0xFF, 0xFF, 10, 0, 0, 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Port != 65535 {
		t.Errorf("expected port 65535, got %d", addr.Port)
	}
}

func TestAddrDecode_ShortData(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80})
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

func TestAddrDecode_EmptyData(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{})
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

// ---- Addr.Encode -----------------------------------------------------------

func TestAddrEncode_IPv4(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "192.168.1.1", Port: 443}
	b := make([]byte, 6)
	err := addr.Encode(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0] != 0x01 || b[1] != 0xBB {
		t.Errorf("expected port 443 (0x01BB), got [%d, %d]", b[0], b[1])
	}
	if b[2] != 192 || b[3] != 168 || b[4] != 1 || b[5] != 1 {
		t.Errorf("expected IP 192.168.1.1, got [%d.%d.%d.%d]", b[2], b[3], b[4], b[5])
	}
}

func TestAddrEncode_Domain(t *testing.T) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 1080}
	b := make([]byte, 6)
	err := addr.Encode(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// SOCKS4A encoding: IP part should be 0.0.0.1
	if b[2] != 0 || b[3] != 0 || b[4] != 0 || b[5] != 1 {
		t.Errorf("expected 0.0.0.1 marker, got [%d.%d.%d.%d]", b[2], b[3], b[4], b[5])
	}
}

func TestAddrEncode_BadHost(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "not-an-ip", Port: 80}
	err := addr.Encode(make([]byte, 6))
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

func TestAddrEncode_IPv6Host(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "::1", Port: 80}
	err := addr.Encode(make([]byte, 6))
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

func TestAddrEncode_UnknownType(t *testing.T) {
	addr := &Addr{Type: 99, Host: "1.2.3.4", Port: 80}
	err := addr.Encode(make([]byte, 6))
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

func TestAddrEncode_ShortBuffer(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	err := addr.Encode(make([]byte, 5))
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

// ---- Addr.String -----------------------------------------------------------

func TestAddrString(t *testing.T) {
	addr := &Addr{Host: "10.0.0.1", Port: 3128}
	if s := addr.String(); s != "10.0.0.1:3128" {
		t.Errorf("expected 10.0.0.1:3128, got %s", s)
	}
}

// ---- readCString -----------------------------------------------------------

func TestReadCString_Normal(t *testing.T) {
	b, err := readCString(bytes.NewReader([]byte("hello\x00")), 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "hello" {
		t.Errorf("expected 'hello', got %q", string(b))
	}
}

func TestReadCString_Empty(t *testing.T) {
	b, err := readCString(bytes.NewReader([]byte{0}), 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty, got %q", string(b))
	}
}

func TestReadCString_AtMaxLen(t *testing.T) {
	// 255 characters + null
	data := make([]byte, 256)
	for i := range 255 {
		data[i] = 'a'
	}
	data[255] = 0
	b, err := readCString(bytes.NewReader(data), 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 255 {
		t.Errorf("expected 255 bytes, got %d", len(b))
	}
}

func TestReadCString_TooLong(t *testing.T) {
	// 256 characters + null → exceeds maxLen+1
	data := make([]byte, 257)
	for i := range 257 {
		data[i] = 'a'
	}
	data[256] = 0
	_, err := readCString(bytes.NewReader(data), 255)
	if !errors.Is(err, ErrFieldTooLong) {
		t.Errorf("expected ErrFieldTooLong, got %v", err)
	}
}

func TestReadCString_EOFBeforeNull(t *testing.T) {
	_, err := readCString(bytes.NewReader([]byte("no-null")), 255)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected EOF or UnexpectedEOF, got %v", err)
	}
}

// ---- NewRequest ------------------------------------------------------------

func TestNewRequest(t *testing.T) {
	addr := &Addr{Host: "1.2.3.4", Port: 80}
	req := NewRequest(CmdConnect, addr, []byte("user"))
	if req.Cmd != CmdConnect {
		t.Errorf("expected CmdConnect, got %d", req.Cmd)
	}
	if req.Addr != addr {
		t.Error("expected same addr pointer")
	}
	if string(req.Userid) != "user" {
		t.Errorf("expected userid 'user', got %q", string(req.Userid))
	}
}

// ---- ReadRequest -----------------------------------------------------------

func TestReadRequest_CONNECT_IPv4(t *testing.T) {
	// VN=4, CD=1, DSTPORT=80, DSTIP=127.0.0.1, USERID="user"\0
	data := []byte{
		4, 1, // VN, CD
		0, 80, // DSTPORT
		127, 0, 0, 1, // DSTIP
		'u', 's', 'e', 'r', 0, // USERID + null
	}
	req, err := ReadRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Cmd != CmdConnect {
		t.Errorf("expected CmdConnect, got %d", req.Cmd)
	}
	if req.Addr.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", req.Addr.Host)
	}
	if req.Addr.Port != 80 {
		t.Errorf("expected port 80, got %d", req.Addr.Port)
	}
	if req.Addr.Type != AddrIPv4 {
		t.Errorf("expected AddrIPv4, got %d", req.Addr.Type)
	}
	if string(req.Userid) != "user" {
		t.Errorf("expected userid 'user', got %q", string(req.Userid))
	}
}

func TestReadRequest_BIND(t *testing.T) {
	data := []byte{
		4, 2, // VN, CD = BIND
		1, 0xBB, // DSTPORT = 443
		10, 0, 0, 1, // DSTIP
		't', 'e', 's', 't', 0, // USERID
	}
	req, err := ReadRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Cmd != CmdBind {
		t.Errorf("expected CmdBind, got %d", req.Cmd)
	}
	if req.Addr.Port != 443 {
		t.Errorf("expected port 443, got %d", req.Addr.Port)
	}
}

func TestReadRequest_SOCKS4A_Domain(t *testing.T) {
	// SOCKS4A: DSTIP = 0.0.0.x (x != 0), followed by hostname after userid
	data := []byte{
		4, 1, // VN, CD
		0, 53, // DSTPORT = 53
		0, 0, 0, 1, // DSTIP = 0.0.0.1 (SOCKS4A marker)
		'u', 0, // USERID + null
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, // hostname + null
	}
	req, err := ReadRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Addr.Type != AddrDomain {
		t.Errorf("expected AddrDomain, got %d", req.Addr.Type)
	}
	if req.Addr.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %s", req.Addr.Host)
	}
	if string(req.Userid) != "u" {
		t.Errorf("expected userid 'u', got %q", string(req.Userid))
	}
}

func TestReadRequest_BadVersion(t *testing.T) {
	data := []byte{5, 1, 0, 80, 127, 0, 0, 1, 'u', 0}
	_, err := ReadRequest(bytes.NewReader(data))
	if !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadRequest_BadCmd(t *testing.T) {
	data := []byte{4, 99, 0, 80, 127, 0, 0, 1, 'u', 0}
	_, err := ReadRequest(bytes.NewReader(data))
	if !errors.Is(err, ErrBadCmd) {
		t.Errorf("expected ErrBadCmd, got %v", err)
	}
}

func TestReadRequest_ShortHeader(t *testing.T) {
	data := []byte{4, 1, 0}
	_, err := ReadRequest(bytes.NewReader(data))
	if err == nil {
		t.Error("expected error for short header")
	}
}

func TestReadRequest_UseridTooLong(t *testing.T) {
	// Header (8) + 256 non-null bytes = exceeds maxUseridLen of 255
	var buf bytes.Buffer
	buf.Write([]byte{4, 1, 0, 80, 127, 0, 0, 1})
	for i := 0; i < 256; i++ {
		buf.WriteByte('a')
	}
	buf.WriteByte(0)
	_, err := ReadRequest(&buf)
	if !errors.Is(err, ErrFieldTooLong) {
		t.Errorf("expected ErrFieldTooLong, got %v", err)
	}
}

func TestReadRequest_DomainTooLong(t *testing.T) {
	// Header + SOCKS4A marker + userid + 256-char hostname
	var buf bytes.Buffer
	buf.Write([]byte{4, 1, 0, 80, 0, 0, 0, 1}) // SOCKS4A marker
	buf.Write([]byte{'u', 0})                     // userid
	for i := 0; i < 256; i++ {
		buf.WriteByte('a')
	}
	buf.WriteByte(0)
	_, err := ReadRequest(&buf)
	if !errors.Is(err, ErrFieldTooLong) {
		t.Errorf("expected ErrFieldTooLong, got %v", err)
	}
}

// ---- Request.Write ---------------------------------------------------------

func TestRequestWrite_CONNECT_IPv4(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "127.0.0.1", Port: 80}
	req := NewRequest(CmdConnect, addr, []byte("user"))

	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-read and verify
	reread, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("failed to re-read written request: %v", err)
	}
	if reread.Cmd != CmdConnect {
		t.Errorf("expected CmdConnect, got %d", reread.Cmd)
	}
	if reread.Addr.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", reread.Addr.Host)
	}
	if reread.Addr.Port != 80 {
		t.Errorf("expected port 80, got %d", reread.Addr.Port)
	}
	if string(reread.Userid) != "user" {
		t.Errorf("expected userid 'user', got %q", string(reread.Userid))
	}
}

func TestRequestWrite_CONNECT_Domain(t *testing.T) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 53}
	req := NewRequest(CmdConnect, addr, []byte("u"))

	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reread, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("failed to re-read written request: %v", err)
	}
	if reread.Addr.Type != AddrDomain {
		t.Errorf("expected AddrDomain, got %d", reread.Addr.Type)
	}
	if reread.Addr.Host != "example.com" {
		t.Errorf("expected 'example.com', got %s", reread.Addr.Host)
	}
}

func TestRequestWrite_NoUserid(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "127.0.0.1", Port: 80}
	req := NewRequest(CmdConnect, addr, nil)

	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reread, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("failed to re-read: %v", err)
	}
	if len(reread.Userid) != 0 {
		t.Errorf("expected empty userid, got %q", string(reread.Userid))
	}
}

func TestRequestWrite_BIND(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 1080}
	req := NewRequest(CmdBind, addr, []byte("test"))

	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reread, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("failed to re-read: %v", err)
	}
	if reread.Cmd != CmdBind {
		t.Errorf("expected CmdBind, got %d", reread.Cmd)
	}
}

func TestRequestWrite_NilAddr(t *testing.T) {
	req := &Request{Cmd: CmdConnect, Userid: []byte("u")}
	err := req.Write(&bytes.Buffer{})
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

func TestRequestWrite_BadHost(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "bad-host", Port: 80}
	req := NewRequest(CmdConnect, addr, []byte("u"))
	err := req.Write(&bytes.Buffer{})
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

// ---- Request.String --------------------------------------------------------

func TestRequestString_Normal(t *testing.T) {
	addr := &Addr{Host: "1.2.3.4", Port: 3128}
	req := NewRequest(CmdConnect, addr, []byte("user"))
	s := req.String()
	if !strings.Contains(s, "1.2.3.4:3128") {
		t.Errorf("expected addr string in output, got: %s", s)
	}
}

func TestRequestString_NilAddr(t *testing.T) {
	req := &Request{Cmd: CmdConnect}
	s := req.String()
	if s == "" {
		t.Error("expected non-empty string for nil addr")
	}
}

// ---- NewReply --------------------------------------------------------------

func TestNewReply(t *testing.T) {
	addr := &Addr{Host: "1.2.3.4", Port: 80}
	reply := NewReply(Granted, addr)
	if reply.Code != Granted {
		t.Errorf("expected Granted, got %d", reply.Code)
	}
	if reply.Addr != addr {
		t.Error("expected same addr pointer")
	}
}

// ---- ReadReply -------------------------------------------------------------

func TestReadReply_Granted(t *testing.T) {
	data := []byte{0, 90, 0, 80, 127, 0, 0, 1}
	reply, err := ReadReply(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.Code != Granted {
		t.Errorf("expected Granted (90), got %d", reply.Code)
	}
	if reply.Addr.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", reply.Addr.Host)
	}
	if reply.Addr.Port != 80 {
		t.Errorf("expected port 80, got %d", reply.Addr.Port)
	}
}

func TestReadReply_Failed(t *testing.T) {
	data := []byte{0, 91, 0, 0, 0, 0, 0, 0}
	reply, err := ReadReply(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.Code != Failed {
		t.Errorf("expected Failed (91), got %d", reply.Code)
	}
}

func TestReadReply_Rejected(t *testing.T) {
	data := []byte{0, 92, 0, 0, 0, 0, 0, 0}
	reply, err := ReadReply(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.Code != Rejected {
		t.Errorf("expected Rejected (92), got %d", reply.Code)
	}
}

func TestReadReply_RejectedUserid(t *testing.T) {
	data := []byte{0, 93, 0, 0, 0, 0, 0, 0}
	reply, err := ReadReply(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.Code != RejectedUserid {
		t.Errorf("expected RejectedUserid (93), got %d", reply.Code)
	}
}

func TestReadReply_BadVersion(t *testing.T) {
	data := []byte{1, 90, 0, 80, 127, 0, 0, 1}
	_, err := ReadReply(bytes.NewReader(data))
	if !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadReply_ShortData(t *testing.T) {
	_, err := ReadReply(bytes.NewReader([]byte{0, 90}))
	if err == nil {
		t.Error("expected error for short data")
	}
}

// ---- Reply.Write -----------------------------------------------------------

func TestReplyWrite_Granted(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "127.0.0.1", Port: 80}
	reply := NewReply(Granted, addr)

	var buf bytes.Buffer
	err := reply.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reread, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("failed to re-read: %v", err)
	}
	if reread.Code != Granted {
		t.Errorf("expected Granted, got %d", reread.Code)
	}
	if reread.Addr.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", reread.Addr.Host)
	}
	if reread.Addr.Port != 80 {
		t.Errorf("expected port 80, got %d", reread.Addr.Port)
	}
}

func TestReplyWrite_NilAddr(t *testing.T) {
	reply := NewReply(Failed, nil)
	var buf bytes.Buffer
	err := reply.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not crash; addr portion is zeroed
	data := buf.Bytes()
	if data[0] != 0 {
		t.Errorf("expected VN=0, got %d", data[0])
	}
	if data[1] != Failed {
		t.Errorf("expected Failed (91), got %d", data[1])
	}
}

func TestReplyWrite_BadHost(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "bad-host", Port: 80}
	reply := NewReply(Failed, addr)
	err := reply.Write(&bytes.Buffer{})
	if !errors.Is(err, ErrBadAddrType) {
		t.Errorf("expected ErrBadAddrType, got %v", err)
	}
}

// ---- Reply.String ----------------------------------------------------------

func TestReplyString_Normal(t *testing.T) {
	addr := &Addr{Host: "1.2.3.4", Port: 80}
	reply := NewReply(Granted, addr)
	s := reply.String()
	if !strings.Contains(s, "1.2.3.4:80") {
		t.Errorf("expected addr in output, got: %s", s)
	}
}

func TestReplyString_NilAddr(t *testing.T) {
	reply := &Reply{Code: Failed}
	s := reply.String()
	if s == "" {
		t.Error("expected non-empty string for nil addr")
	}
}

// ---- Constant values -------------------------------------------------------

func TestConstants_Ver4(t *testing.T) {
	if Ver4 != 4 {
		t.Errorf("Ver4 should be 4, got %d", Ver4)
	}
}

func TestConstants_Commands(t *testing.T) {
	if CmdConnect != 1 {
		t.Errorf("CmdConnect should be 1, got %d", CmdConnect)
	}
	if CmdBind != 2 {
		t.Errorf("CmdBind should be 2, got %d", CmdBind)
	}
}

func TestConstants_AddrTypes(t *testing.T) {
	if AddrIPv4 != 0 {
		t.Errorf("AddrIPv4 should be 0, got %d", AddrIPv4)
	}
	if AddrDomain != 1 {
		t.Errorf("AddrDomain should be 1, got %d", AddrDomain)
	}
}

func TestConstants_ReplyCodes(t *testing.T) {
	if Granted != 90 {
		t.Errorf("Granted should be 90, got %d", Granted)
	}
	if Failed != 91 {
		t.Errorf("Failed should be 91, got %d", Failed)
	}
	if Rejected != 92 {
		t.Errorf("Rejected should be 92, got %d", Rejected)
	}
	if RejectedUserid != 93 {
		t.Errorf("RejectedUserid should be 93, got %d", RejectedUserid)
	}
}

// ---- Round-trip: Addr Encode → Decode --------------------------------------

func TestAddrRoundtrip_IPv4(t *testing.T) {
	original := &Addr{Type: AddrIPv4, Host: "172.16.0.1", Port: 8080}
	b := make([]byte, 6)
	if err := original.Encode(b); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded := &Addr{}
	if err := decoded.Decode(b); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded.Host != "172.16.0.1" {
		t.Errorf("expected 172.16.0.1, got %s", decoded.Host)
	}
	if decoded.Port != 8080 {
		t.Errorf("expected port 8080, got %d", decoded.Port)
	}
	if decoded.Type != AddrIPv4 {
		t.Errorf("expected AddrIPv4, got %d", decoded.Type)
	}
}

// ---- Round-trip: Request Write → ReadRequest -------------------------------

func TestRequestRoundtrip_SOCKS4A(t *testing.T) {
	addr := &Addr{Type: AddrDomain, Host: "test.local", Port: 1080}
	original := NewRequest(CmdConnect, addr, []byte("socksuser"))

	var buf bytes.Buffer
	if err := original.Write(&buf); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reparsed, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if reparsed.Cmd != CmdConnect {
		t.Errorf("expected CmdConnect, got %d", reparsed.Cmd)
	}
	if reparsed.Addr.Type != AddrDomain {
		t.Errorf("expected AddrDomain, got %d", reparsed.Addr.Type)
	}
	if reparsed.Addr.Host != "test.local" {
		t.Errorf("expected 'test.local', got %s", reparsed.Addr.Host)
	}
	if reparsed.Addr.Port != 1080 {
		t.Errorf("expected port 1080, got %d", reparsed.Addr.Port)
	}
	if string(reparsed.Userid) != "socksuser" {
		t.Errorf("expected 'socksuser', got %q", string(reparsed.Userid))
	}
}

func TestRequestRoundtrip_EmptyUserid(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "10.10.10.10", Port: 9999}
	original := NewRequest(CmdBind, addr, []byte{})

	var buf bytes.Buffer
	if err := original.Write(&buf); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reparsed, err := ReadRequest(&buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(reparsed.Userid) != 0 {
		t.Errorf("expected empty userid, got %q", string(reparsed.Userid))
	}
}

// ---- Round-trip: Reply Write → ReadReply -----------------------------------

func TestReplyRoundtrip_Failed(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0}
	original := NewReply(Failed, addr)

	var buf bytes.Buffer
	if err := original.Write(&buf); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reparsed, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if reparsed.Code != Failed {
		t.Errorf("expected Failed, got %d", reparsed.Code)
	}
	if reparsed.Addr.Host != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0, got %s", reparsed.Addr.Host)
	}
}

// ---- ReadRequest edge cases -------------------------------------------------

func TestReadRequest_SOCKS4A_DomainEOF(t *testing.T) {
	// SOCKS4A marker set, userid reads OK, but domain hostname has no null terminator
	var buf bytes.Buffer
	buf.Write([]byte{4, 1, 0, 80, 0, 0, 0, 1}) // SOCKS4A marker
	buf.Write([]byte{'u', 0})                     // userid
	buf.Write([]byte("no-null"))                  // domain with no null terminator
	_, err := ReadRequest(&buf)
	if err == nil {
		t.Error("expected error for incomplete domain hostname")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected EOF-related error, got %v", err)
	}
}

func TestReadRequest_SOCKS4A_NoDomainData(t *testing.T) {
	// SOCKS4A marker set, userid reads OK, but no domain data at all
	var buf bytes.Buffer
	buf.Write([]byte{4, 1, 0, 80, 0, 0, 0, 1}) // SOCKS4A marker
	buf.Write([]byte{'u', 0})                     // userid, no hostname bytes follow
	_, err := ReadRequest(&buf)
	if err == nil {
		t.Error("expected error for missing domain hostname")
	}
}

func TestReadRequest_HeaderEOF(t *testing.T) {
	_, err := ReadRequest(bytes.NewReader([]byte{4}))
	if err == nil {
		t.Error("expected error for 1-byte header")
	}
}

// ---- AddrDecode edge cases --------------------------------------------------

func TestAddrDecode_ZeroFirstOctetNotSocks4A(t *testing.T) {
	// 0.2.0.0:80 — first octet is 0 but others are non-zero, NOT SOCKS4A
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80, 0, 2, 0, 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Type != AddrIPv4 {
		t.Errorf("expected AddrIPv4, got %d", addr.Type)
	}
	if addr.Host != "0.2.0.0" {
		t.Errorf("expected 0.2.0.0, got %s", addr.Host)
	}
}

func TestAddrDecode_ZeroThirdOctetNotSocks4A(t *testing.T) {
	// 1.2.3.0:80 — Socks4A check: b[2]|b[3]|b[4]==0, b[2]=1 so NOT SOCKS4A
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80, 1, 0, 3, 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.Type != AddrIPv4 {
		t.Errorf("expected AddrIPv4, got %d", addr.Type)
	}
}

func TestAddrDecode_FiveBytes(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode([]byte{0, 80, 127, 0, 0})
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

func TestAddrDecode_NilInput(t *testing.T) {
	addr := &Addr{}
	err := addr.Decode(nil)
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

// ---- AddrEncode edge cases --------------------------------------------------

func TestAddrEncode_ZeroBuffer(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	err := addr.Encode(nil)
	if !errors.Is(err, ErrShortDataLength) {
		t.Errorf("expected ErrShortDataLength, got %v", err)
	}
}

func TestAddrEncode_DomainZeroIP(t *testing.T) {
	// AddrDomain always encodes 0.0.0.1 as IP marker
	addr := &Addr{Type: AddrDomain, Host: "any.host.name", Port: 443}
	b := make([]byte, 6)
	err := addr.Encode(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[2] != 0 || b[3] != 0 || b[4] != 0 || b[5] != 1 {
		t.Errorf("expected 0.0.0.1 SOCKS4A marker, got %d.%d.%d.%d", b[2], b[3], b[4], b[5])
	}
}

// ---- Request.Write edge cases -----------------------------------------------

func TestRequestWrite_BadCmd(t *testing.T) {
	// Invalid command byte still serializes (encoding doesn't validate cmd)
	addr := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	req := NewRequest(99, addr, []byte("user"))
	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify raw bytes: VN(4) + CD(99) at offset 0 and 1
	data := buf.Bytes()
	if data[0] != Ver4 {
		t.Errorf("expected VN=4, got %d", data[0])
	}
	if data[1] != 99 {
		t.Errorf("expected CD=99, got %d", data[1])
	}
}

func TestRequestWrite_LongUserid(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	longUserid := make([]byte, 300)
	for i := range longUserid {
		longUserid[i] = 'x'
	}
	req := NewRequest(CmdConnect, addr, longUserid)
	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Wire format doesn't enforce maxUseridLen on write
	if buf.Len() < 300 {
		t.Errorf("expected at least 300 bytes, got %d", buf.Len())
	}
}

// ---- Reply.Write edge cases -------------------------------------------------

func TestReplyWrite_RejectedUserid(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0}
	reply := NewReply(RejectedUserid, addr)
	var buf bytes.Buffer
	err := reply.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reread, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("re-read failed: %v", err)
	}
	if reread.Code != RejectedUserid {
		t.Errorf("expected RejectedUserid (93), got %d", reread.Code)
	}
}

func TestReplyWrite_Rejected(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0}
	reply := NewReply(Rejected, addr)
	var buf bytes.Buffer
	err := reply.Write(&buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reread, err := ReadReply(&buf)
	if err != nil {
		t.Fatalf("re-read failed: %v", err)
	}
	if reread.Code != Rejected {
		t.Errorf("expected Rejected (92), got %d", reread.Code)
	}
}

// ---- Addr String edge cases -------------------------------------------------

func TestAddrString_ZeroPort(t *testing.T) {
	addr := &Addr{Host: "10.0.0.1", Port: 0}
	if s := addr.String(); s != "10.0.0.1:0" {
		t.Errorf("expected 10.0.0.1:0, got %s", s)
	}
}

func TestAddrString_Domain(t *testing.T) {
	addr := &Addr{Host: "example.com", Port: 443}
	if s := addr.String(); s != "example.com:443" {
		t.Errorf("expected example.com:443, got %s", s)
	}
}

// ---- ReadCString edge cases -------------------------------------------------

func TestReadCString_ZeroMaxLen(t *testing.T) {
	// maxLen=0: can read exactly 1 byte before limit
	b, err := readCString(bytes.NewReader([]byte{0}), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty, got %q", string(b))
	}
}

func TestReadCString_ZeroMaxLen_WithData(t *testing.T) {
	// maxLen=0, first byte is non-null → immediately exceeds limit
	_, err := readCString(bytes.NewReader([]byte{'x'}), 0)
	if !errors.Is(err, ErrFieldTooLong) {
		t.Errorf("expected ErrFieldTooLong, got %v", err)
	}
}

func TestReadCString_MidNull(t *testing.T) {
	b, err := readCString(bytes.NewReader([]byte("ab\x00cd")), 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "ab" {
		t.Errorf("expected 'ab', got %q", string(b))
	}
}

func TestReadCString_SingleChar(t *testing.T) {
	b, err := readCString(bytes.NewReader([]byte{'x', 0}), 255)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "x" {
		t.Errorf("expected 'x', got %q", string(b))
	}
}

// ---- Request.String edge cases -----------------------------------------------

func TestRequestString_Domain(t *testing.T) {
	addr := &Addr{Host: "test.example.com", Port: 1080}
	req := NewRequest(CmdBind, addr, []byte("socksuser"))
	s := req.String()
	if !strings.Contains(s, "test.example.com:1080") {
		t.Errorf("expected domain addr in output, got: %s", s)
	}
	if !strings.Contains(s, "4 2") {
		t.Errorf("expected '4 2' prefix (Ver4, CmdBind), got: %s", s)
	}
}

// ---- Reply.String edge cases ------------------------------------------------

func TestReplyString_Rejected(t *testing.T) {
	addr := &Addr{Host: "0.0.0.0", Port: 0}
	reply := NewReply(Rejected, addr)
	s := reply.String()
	if !strings.Contains(s, "92") {
		t.Errorf("expected '92' (Rejected) in output, got: %s", s)
	}
}

// ---- Benchmarks ------------------------------------------------------------

func BenchmarkReadRequest_CONNECT_IPv4(b *testing.B) {
	data := []byte{4, 1, 0, 80, 127, 0, 0, 1, 'u', 's', 'e', 'r', 0}
	r := bytes.NewReader(data)
	b.ResetTimer()
	for b.Loop() {
		r.Reset(data)
		ReadRequest(r)
	}
}

func BenchmarkReadRequest_SOCKS4A(b *testing.B) {
	data := []byte{4, 1, 0, 53, 0, 0, 0, 1, 'u', 0, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0}
	r := bytes.NewReader(data)
	b.ResetTimer()
	for b.Loop() {
		r.Reset(data)
		ReadRequest(r)
	}
}

func BenchmarkReadRequest_BIND(b *testing.B) {
	data := []byte{4, 2, 0, 80, 10, 0, 0, 1, 'u', 's', 'e', 'r', 0}
	r := bytes.NewReader(data)
	b.ResetTimer()
	for b.Loop() {
		r.Reset(data)
		ReadRequest(r)
	}
}

func BenchmarkRequestWrite_CONNECT_IPv4(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "127.0.0.1", Port: 80}
	req := NewRequest(CmdConnect, addr, []byte("user"))
	b.ResetTimer()
	for b.Loop() {
		req.Write(io.Discard)
	}
}

func BenchmarkRequestWrite_CONNECT_Domain(b *testing.B) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 53}
	req := NewRequest(CmdConnect, addr, []byte("u"))
	b.ResetTimer()
	for b.Loop() {
		req.Write(io.Discard)
	}
}

func BenchmarkRequestWrite_BIND(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 1080}
	req := NewRequest(CmdBind, addr, []byte("test"))
	b.ResetTimer()
	for b.Loop() {
		req.Write(io.Discard)
	}
}

func BenchmarkReadReply(b *testing.B) {
	data := []byte{0, 90, 0, 80, 127, 0, 0, 1}
	r := bytes.NewReader(data)
	b.ResetTimer()
	for b.Loop() {
		r.Reset(data)
		ReadReply(r)
	}
}

func BenchmarkReplyWrite(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "127.0.0.1", Port: 80}
	reply := NewReply(Granted, addr)
	b.ResetTimer()
	for b.Loop() {
		reply.Write(io.Discard)
	}
}

func BenchmarkAddrDecode(b *testing.B) {
	data := []byte{0, 80, 127, 0, 0, 1}
	b.ResetTimer()
	for b.Loop() {
		addr := &Addr{}
		addr.Decode(data)
	}
}

func BenchmarkAddrEncode_IPv4(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "192.168.1.1", Port: 443}
	buf := make([]byte, 6)
	b.ResetTimer()
	for b.Loop() {
		addr.Encode(buf)
	}
}

func BenchmarkAddrEncode_Domain(b *testing.B) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 1080}
	buf := make([]byte, 6)
	b.ResetTimer()
	for b.Loop() {
		addr.Encode(buf)
	}
}

func BenchmarkAddrString(b *testing.B) {
	addr := &Addr{Host: "10.0.0.1", Port: 3128}
	b.ResetTimer()
	for b.Loop() {
		_ = addr.String()
	}
}

func BenchmarkReadCString(b *testing.B) {
	data := []byte("hello\x00")
	r := bytes.NewReader(data)
	b.ResetTimer()
	for b.Loop() {
		r.Reset(data)
		readCString(r, 255)
	}
}

func BenchmarkRequestString(b *testing.B) {
	addr := &Addr{Host: "10.0.0.1", Port: 3128}
	req := NewRequest(CmdConnect, addr, []byte("user"))
	b.ResetTimer()
	for b.Loop() {
		_ = req.String()
	}
}

func BenchmarkReplyString(b *testing.B) {
	addr := &Addr{Host: "10.0.0.1", Port: 3128}
	reply := NewReply(Granted, addr)
	b.ResetTimer()
	for b.Loop() {
		_ = reply.String()
	}
}
