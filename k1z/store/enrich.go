package store

import (
	"net"
	"sync"
)

var enrichOnce sync.Map // value → done

// EnrichAssetDNS resolves domain/subdomain assets into IP nodes (best-effort,
// once per value per process — ScopeWeaver enrich concept, DNS part).
// enrichSem caps concurrent DNS enrichment workers well below the 8-connection pool.
var enrichSem = make(chan struct{}, 4)

func (s *Store) EnrichAssetDNS(a Asset) {
	if a.Type != "domain" && a.Type != "subdomain" && a.Type != "site" {
		return
	}
	if _, done := enrichOnce.LoadOrStore(a.Type+"|"+a.Value, true); done {
		return
	}
	go func() {
		enrichSem <- struct{}{} // bound concurrent lookups+writes (was one goroutine per asset, unbounded)
		defer func() { <-enrichSem }()
		ips, err := net.LookupHost(a.Value)
		if err != nil {
			return
		}
		for _, ip := range ips {
			_ = s.UpsertAsset(&Asset{
				CompanyID: a.CompanyID, Type: "ip", Value: ip,
				Meta: `{"parent":"` + a.Value + `"}`, Source: "dns-enrich",
			})
		}
	}()
}
