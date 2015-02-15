package main

import (
	"github.com/sebcat/dns/dnsscanner"
	"log"
	"net"
)

func main() {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	m := dnsscanner.NewQuery("www.detectify.com", dnsscanner.ANY, dnsscanner.IN)

	if err := m.Send(conn); err != nil {
		log.Fatal(err)
	}
}
