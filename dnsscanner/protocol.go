package dnsscanner

import (
	"io"
	"strings"
)

// Types
const (
	A     uint16 = 1
	NS           = 2
	MD           = 3
	MF           = 4
	CNAME        = 5
	SOA          = 6
	MB           = 7
	MG           = 8
	MR           = 9
	NULL         = 10
	WKS          = 11
	PTR          = 12
	HINFO        = 13
	MINFO        = 14
	MX           = 15
	TXT          = 16
	AAAA         = 28
	AXFR         = 252
	MAILB        = 253
	MAILA        = 254
)

//Classes
const (
	IN uint16 = 1
	CS        = 2
	CH        = 3
	HS        = 4
)

// Both type and class
const ANY uint16 = 255

type Label []byte

// Convert a string to a sequence of DNS labels
func Labelize(name string) (res []Label) {
	for _, section := range strings.Split(name, ".") {
		s := []byte{byte(len(section))}
		s = append(s, []byte(section)...)
		res = append(res, Label(s))
	}

	res = append(res, Label([]byte{0}))

	return
}

// QR
const (
	Query    = 0
	Response = 1
)

//OPCODEs
const (
	QUERY  = 0
	IQUERY = 1
	STATUS = 2
)

// RCODEs
const (
	NoError        = 0
	FormatError    = 1
	ServerFailure  = 2
	NameError      = 3
	NotImplemented = 4
	Refused        = 5
)

type Header struct {
	ID      uint16
	QR      byte
	OPCODE  byte
	AA      byte
	TC      byte
	RD      byte
	RA      byte
	RCODE   byte
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (h *Header) MarshalBinary() (data []byte, err error) {
	data = []byte{
		byte(h.ID >> 8), byte(h.ID & 0xff),
		byte(h.QR<<7 | h.OPCODE<<6 | h.AA<<2 | h.TC<<1 | h.RD),
		byte(h.RA<<7 | (h.RCODE & 0x0f)),
		byte(h.QDCOUNT >> 8), byte(h.QDCOUNT & 0xff),
		byte(h.ANCOUNT >> 8), byte(h.ANCOUNT & 0xff),
		byte(h.NSCOUNT >> 8), byte(h.NSCOUNT & 0xff),
		byte(h.ARCOUNT >> 8), byte(h.ARCOUNT & 0xff),
	}

	return
}

type Question struct {
	QNAME  []Label
	QTYPE  uint16
	QCLASS uint16
}

func (q *Question) MarshalBinary() (data []byte, err error) {
	for _, label := range q.QNAME {
		data = append(data, []byte(label)...)
	}

	data = append(data,
		[]byte{
			byte(q.QTYPE >> 8), byte(q.QTYPE & 0xff),
			byte(q.QCLASS >> 8), byte(q.QCLASS & 0xff)}...)
	return
}

type Message struct {
	Header   Header
	Question Question
	// TODO: add missing fields
}

func (m *Message) MarshalBinary() (data []byte, err error) {
	if hdr, err := m.Header.MarshalBinary(); err != nil {
		return nil, err
	} else {
		data = append(data, hdr...)
	}

	if q, err := m.Question.MarshalBinary(); err != nil {
		return nil, err
	} else {
		data = append(data, q...)
	}

	return
}

func (m *Message) Send(w io.Writer) error {
	if b, err := m.MarshalBinary(); err != nil {
		return err
	} else {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}

	return nil
}

func NewQuery(label string, t, c uint16) *Message {
	return &Message{
		Header: Header{
			ID:      0xabcd,
			RD:      1,
			QDCOUNT: 1,
		},
		Question: Question{
			QNAME:  Labelize(label),
			QTYPE:  t,
			QCLASS: c,
		},
	}
}

func Receive(r io.Reader) (msg *Message, err error) {
	// TODO: Implement
	return
}
