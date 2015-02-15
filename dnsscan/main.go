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
	nsaddr  = flag.String("server", "8.8.8.8:53", "DNS server")
	nsproto = flag.String("proto", "udp", "transport layer protocol")
	ttl     = flag.Duration("timeout", 10*time.Second, "dial and connection timeout")
	nsclass = flag.String("class", "IN", "name class")
	nstype  = flag.String("type", "ANY", "name type")
)

func lookup(wg *sync.WaitGroup, proto, addr string, timeout time.Duration, query *dnsscanner.Message) {
	defer wg.Done()
	conn, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := query.Send(conn); err != nil {
		log.Println(err)
		return
	}

	if resp, err := dnsscanner.Receive(conn); err != nil {
		log.Println("ERR", err)
	} else {
		log.Println("OK", resp)
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("no names given")
	}

	c, err := dnsscanner.ClassFromString(*nsclass)
	if err != nil {
		log.Fatal(err)
	}

	t, err := dnsscanner.TypeFromString(*nstype)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(len(args))
	for _, name := range flag.Args() {
		q := dnsscanner.NewQuery(name, t, c)
		go lookup(&wg, *nsproto, *nsaddr, *ttl, q)
	}

	wg.Wait()
}
