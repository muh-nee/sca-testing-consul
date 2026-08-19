// Command reachability-fixture is a minimal, isolated Go module used to exercise
// datadog-sbom-generator's reachable-symbols detection against real, OSV-verified advisories.
// See README.md for the exact advisory/symbol matrix this program is designed to hit.
package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

func main() {
	go serveDNS()
	serveHTTP()
}

func serveHTTP() {
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func serveDNS() {
	mux := dns.NewServeMux()
	mux.HandleFunc(dns.Fqdn("example.com"), handleDNSRequest)
	if err := dns.ListenAndServe(":5353", "udp", mux); err != nil {
		log.Fatal(err)
	}
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	_ = w.WriteMsg(m)
}
