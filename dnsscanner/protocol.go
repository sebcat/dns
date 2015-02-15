package dnsscanner

import (
	"errors"
	"io"
	"strconv"
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

	RP    = 17
	AFSDB = 18
	SIG   = 24
	KEY   = 25

	AAAA = 28

	LOC        = 29
	SRV        = 33
	NAPTR      = 35
	KX         = 36
	CERT       = 37
	DNAME      = 39
	APL        = 42
	DS         = 43
	SSHFP      = 44
	IPSECKEY   = 45
	RRSIG      = 46
	NSEC       = 47
	DNSKEY     = 48
	DHCID      = 49
	NSEC3      = 50
	NSEC3PARAM = 51
	TLSA       = 52
	HIP        = 55
	CDS        = 59
	CDNSKEY    = 60
	TKEY       = 249
	TSIG       = 250

	AXFR  = 252
	MAILB = 253
	MAILA = 254

	CAA = 257
	TA  = 32768
	DLV = 32769
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

func TypeToString(t uint16) string {
	switch t {
	case A:
		return "A"
	case NS:
		return "NS"
	case MD:
		return "MD"
	case MF:
		return "MF"
	case CNAME:
		return "CNAME"
	case SOA:
		return "SOA"
	case MB:
		return "MB"
	case MG:
		return "MG"
	case MR:
		return "MR"
	case NULL:
		return "NULL"
	case WKS:
		return "WKS"
	case PTR:
		return "PTR"
	case HINFO:
		return "HINFO"
	case MINFO:
		return "MINFO"
	case MX:
		return "MX"
	case TXT:
		return "TXT"
	case RP:
		return "RP"
	case AFSDB:
		return "AFSDB"
	case SIG:
		return "SIG"
	case KEY:
		return "KEY"
	case AAAA:
		return "AAAA"
	case LOC:
		return "LOC"
	case SRV:
		return "SRV"
	case NAPTR:
		return "NAPTR"
	case KX:
		return "KX"
	case CERT:
		return "CERT"
	case DNAME:
		return "DNAME"
	case APL:
		return "APL"
	case DS:
		return "DS"
	case SSHFP:
		return "SSHFP"
	case IPSECKEY:
		return "IPSECKEY"
	case RRSIG:
		return "RRSIG"
	case NSEC:
		return "NSEC"
	case DNSKEY:
		return "DNSKEY"
	case DHCID:
		return "DHCID"
	case NSEC3:
		return "NSEC3"
	case NSEC3PARAM:
		return "NSEC3PARAM"
	case TLSA:
		return "TLSA"
	case HIP:
		return "HIP"
	case CDS:
		return "CDS"
	case CDNSKEY:
		return "CDNSKEY"
	case TKEY:
		return "TKEY"
	case TSIG:
		return "TSIG"
	case AXFR:
		return "AXFR"
	case MAILB:
		return "MAILB"
	case MAILA:
		return "MAILA"
	case ANY:
		return "ANY"
	case CAA:
		return "CAA"
	case TA:
		return "TA"
	case DLV:
		return "DLV"
	default:
		return "<" + strconv.Itoa(int(t)) + ">"
	}
}

func TypeFromString(str string) (val uint16, err error) {
	switch strings.ToUpper(str) {
	case "A":
		val = A
	case "NS":
		val = NS
	case "MD":
		val = MD
	case "MF":
		val = MF
	case "CNAME":
		val = CNAME
	case "SOA":
		val = SOA
	case "MB":
		val = MB
	case "MG":
		val = MG
	case "MR":
		val = MR
	case "NULL":
		val = NULL
	case "WKS":
		val = WKS
	case "PTR":
		val = PTR
	case "HINFO":
		val = HINFO
	case "MINFO":
		val = MINFO
	case "MX":
		val = MX
	case "TXT":
		val = TXT
	case "RP":
		val = RP
	case "AFSDB":
		val = AFSDB
	case "SIG":
		val = SIG
	case "KEY":
		val = KEY
	case "AAAA":
		val = AAAA
	case "LOC":
		val = LOC
	case "SRV":
		val = SRV
	case "NAPTR":
		val = NAPTR
	case "KX":
		val = KX
	case "CERT":
		val = CERT
	case "DNAME":
		val = DNAME
	case "APL":
		val = APL
	case "DS":
		val = DS
	case "SSHFP":
		val = SSHFP
	case "IPSECKEY":
		val = IPSECKEY
	case "RRSIG":
		val = RRSIG
	case "NSEC":
		val = NSEC
	case "DNSKEY":
		val = DNSKEY
	case "DHCID":
		val = DHCID
	case "NSEC3":
		val = NSEC3
	case "NSEC3PARAM":
		val = NSEC3PARAM
	case "TLSA":
		val = TLSA
	case "HIP":
		val = HIP
	case "CDS":
		val = CDS
	case "CONSKEY":
		val = CDNSKEY
	case "TKEY":
		val = TKEY
	case "TSIG":
		val = TSIG
	case "AXFR":
		val = AXFR
	case "MAILB":
		val = MAILB
	case "MAILA":
		val = MAILA
	case "ANY":
		val = ANY
	case "CAA":
		val = CAA
	case "TA":
		val = TA
	case "DLV":
		val = DLV
	default:
		err = errors.New("unknown TYPE")
	}

	return
}

func ClassToString(c uint16) string {
	switch c {
	case IN:
		return "IN"
	case CS:
		return "CS"
	case CH:
		return "CH"
	case HS:
		return "HS"
	case ANY:
		return "ANY"
	default:
		return "<" + strconv.Itoa(int(c)) + ">"
	}
}

func ClassFromString(str string) (val uint16, err error) {
	switch strings.ToUpper(str) {
	case "IN":
		val = IN
	case "CS":
		val = CS
	case "CH":
		val = CH
	case "HS":
		val = HS
	case "ANY":
		val = ANY
	default:
		err = errors.New("unknown CLASS")
	}

	return
}

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
