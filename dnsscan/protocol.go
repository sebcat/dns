package dnsscan

import (
	"strings"
)

type QType uint16

const (
	A     QType = 1
	NS          = 2
	MD          = 3
	MF          = 4
	CNAME       = 5
	SOA         = 6
	MB          = 7
	MG          = 8
	MR          = 9
	NULL        = 10
	WKS         = 11
	PTR         = 12
	HINFO       = 13
	MINFO       = 14
	MX          = 15
	TXT         = 16
	AXFR        = 252
	MAILB       = 253
	MAILA       = 254
	TSTAR       = 255
)

type QClass uint16

const (
	IN    QClass = 1
	CS           = 2
	CH           = 3
	HS           = 4
	CSTAR        = 255
)

type Label []byte

// Convert a string to a sequence of DNS labels
func Labelize(name string) (res []Label) {
	for _, section := range strings.Split(name, ".") {
		s := []byte{byte(len(section))}
		s = append(s, []byte(section)...)
		res = append(res, Label(s))
	}

	return
}

type QR int

const (
	QRQuery    QR = 0
	QRResponse    = 1
)

type Header struct {
	ID uint16
	QR QR
}

type Question struct {
	QNAME  []Label
	QTYPE  QType
	QCLASS QClass
}

type Message struct {
	Header   Header
	Question Question
}
