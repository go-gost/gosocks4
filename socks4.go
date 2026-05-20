// SOCKS Protocol Version 4(a)
// https://www.openssh.com/txt/socks4.protocol
// https://www.openssh.com/txt/socks4a.protocol
package gosocks4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	Ver4 = 4
)

const (
	CmdConnect uint8 = 1
	CmdBind          = 2
)

const (
	AddrIPv4   = 0
	AddrDomain = 1
)

const (
	Granted        = 90
	Failed         = 91
	Rejected       = 92
	RejectedUserid = 93
)

const (
	maxUseridLen   = 255
	maxHostnameLen = 255
)

var (
	ErrBadVersion      = errors.New("Bad version")
	ErrBadAddrType     = errors.New("Bad address type")
	ErrShortDataLength = errors.New("Short data length")
	ErrBadCmd          = errors.New("Bad Command")
	ErrFieldTooLong    = errors.New("Field too long")
)

type Addr struct {
	Type int
	Host string
	Port uint16
	ip4  [4]byte
}

func (addr *Addr) Decode(b []byte) error {
	if len(b) < 6 {
		return ErrShortDataLength
	}

	addr.Port = binary.BigEndian.Uint16(b[0:2])
	addr.Host = net.IP(b[2 : 2+net.IPv4len]).String()
	copy(addr.ip4[:], b[2:6])

	if b[2]|b[3]|b[4] == 0 && b[5] != 0 {
		addr.Type = AddrDomain
	}

	return nil
}

func (addr *Addr) Encode(b []byte) error {
	if len(b) < 6 {
		return ErrShortDataLength
	}

	binary.BigEndian.PutUint16(b[0:2], addr.Port)

	switch addr.Type {
	case AddrIPv4:
		if ip := addr.ip4; ip[0]|ip[1]|ip[2]|ip[3] != 0 {
			copy(b[2:], ip[:])
		} else {
			ip4 := net.ParseIP(addr.Host).To4()
			if ip4 == nil {
				return ErrBadAddrType
			}
			copy(b[2:], ip4)
		}
	case AddrDomain:
		ip4 := net.IPv4(0, 0, 0, 1)
		copy(b[2:], ip4.To4())
	default:
		return ErrBadAddrType
	}

	return nil
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
}

/*
 +----+----+----+----+----+----+----+----+----+----+....+----+
 | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
 +----+----+----+----+----+----+----+----+----+----+....+----+
    1    1      2              4           variable       1
*/
type Request struct {
	Cmd    uint8
	Addr   *Addr
	Userid []byte
}

func NewRequest(cmd uint8, addr *Addr, userid []byte) *Request {
	return &Request{
		Cmd:    cmd,
		Addr:   addr,
		Userid: userid,
	}
}

func readCString(r io.Reader, maxLen int) ([]byte, error) {
	var buf [256]byte
	var b [1]byte
	for i := 0; i <= maxLen; i++ {
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			if i == 0 {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		if b[0] == 0 {
			if i == 0 {
				return nil, nil
			}
			result := make([]byte, i)
			copy(result, buf[:i])
			return result, nil
		}
		buf[i] = b[0]
	}
	return nil, ErrFieldTooLong
}

func ReadRequest(r io.Reader) (*Request, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	if hdr[0] != Ver4 {
		return nil, ErrBadVersion
	}

	switch hdr[1] {
	case CmdConnect, CmdBind:
	default:
		return nil, ErrBadCmd
	}

	request := &Request{
		Cmd: hdr[1],
	}

	request.Addr = &Addr{}
	_ = request.Addr.Decode(hdr[2:8])

	b, err := readCString(r, maxUseridLen)
	if err != nil {
		return nil, err
	}
	request.Userid = b

	if request.Addr.Type == AddrDomain {
		b, err = readCString(r, maxHostnameLen)
		if err != nil {
			return nil, err
		}
		request.Addr.Host = string(b)
	}

	return request, nil
}

func (r *Request) Write(w io.Writer) (err error) {
	if r.Addr == nil {
		return ErrBadAddrType
	}

	var buf bytes.Buffer
	size := 1 + 1 + 6 + len(r.Userid) + 1 // VN + CD + addr + userid + null
	if r.Addr.Type == AddrDomain {
		size += len(r.Addr.Host) + 1 // hostname + null
	}
	buf.Grow(size)
	buf.WriteByte(Ver4)
	buf.WriteByte(r.Cmd)

	var b [6]byte
	if err = r.Addr.Encode(b[:]); err != nil {
		return
	}
	buf.Write(b[:])

	if len(r.Userid) > 0 {
		buf.Write(r.Userid)
	}
	buf.WriteByte(0)

	if r.Addr.Type == AddrDomain {
		buf.WriteString(r.Addr.Host)
		buf.WriteByte(0)
	}

	_, err = buf.WriteTo(w)
	return
}

func (r *Request) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	var buf strings.Builder
	buf.Grow(32)
	buf.WriteString("4 ")
	buf.WriteByte('0' + byte(r.Cmd))
	buf.WriteByte(' ')
	buf.WriteString(addr.String())
	return buf.String()
}

/*
 +----+----+----+----+----+----+----+----+
 | VN | CD | DSTPORT |      DSTIP        |
 +----+----+----+----+----+----+----+----+
 	1    1      2              4
*/
type Reply struct {
	Code uint8
	Addr *Addr
}

func NewReply(code uint8, addr *Addr) *Reply {
	return &Reply{
		Code: code,
		Addr: addr,
	}
}

func ReadReply(r io.Reader) (*Reply, error) {
	var b [8]byte

	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return nil, err
	}

	if b[0] != 0 {
		return nil, ErrBadVersion
	}

	reply := &Reply{
		Code: b[1],
	}

	reply.Addr = &Addr{}
	_ = reply.Addr.Decode(b[2:])

	return reply, nil
}

func (r *Reply) Write(w io.Writer) (err error) {
	var b [8]byte

	b[1] = r.Code
	if r.Addr != nil {
		if err = r.Addr.Encode(b[2:]); err != nil {
			return
		}
	}

	_, err = w.Write(b[:])
	return
}

func (r *Reply) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	var buf strings.Builder
	buf.Grow(32)
	buf.WriteString("0 ")
	buf.WriteString(strconv.Itoa(int(r.Code)))
	buf.WriteByte(' ')
	buf.WriteString(addr.String())
	return buf.String()
}
