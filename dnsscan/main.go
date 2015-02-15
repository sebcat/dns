package main

import (
	"github.com/sebcat/dns/dnsscanner"
	"log"
	"net"
)

func main() {
	m := dnsscanner.Message{
		Header: dnsscanner.Header{
			ID:      0xabcd,
			RD:      1,
			QDCOUNT: 1,
		},
		Question: dnsscanner.Question{
			QNAME:  dnsscanner.Labelize("www.detectify.com"),
			QTYPE:  dnsscanner.A,
			QCLASS: dnsscanner.IN,
		},
	}

	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	if err := m.Send(conn); err != nil {
		log.Fatal(err)
	}
}
