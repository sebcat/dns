package main

import (
	"flag"
	"github.com/sebcat/dns/dnsscanner"
	"log"
	"net"
	"sync"
	"time"
)

var (
	nsaddr  = flag.String("ns", "8.8.8.8:53", "DNS server")
	nsproto = flag.String("proto", "udp", "transport layer protocol")
	ttl     = flag.Duration("timeout", 10*time.Second, "dial and connection timeout")
)

func lookup(wg *sync.WaitGroup, proto, addr, name string, timeout time.Duration) {
	defer wg.Done()
	conn, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()

	m := dnsscanner.NewQuery(name, dnsscanner.ANY, dnsscanner.IN)
	if err := m.Send(conn); err != nil {
		log.Println(err)
		return
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("no names given")
	}

	var wg sync.WaitGroup
	wg.Add(len(args))
	for _, name := range flag.Args() {
		go lookup(&wg, *nsproto, *nsaddr, name, *ttl)
	}

	wg.Wait()
}
