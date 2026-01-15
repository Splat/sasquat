package verify

import (
	"context"
	"net"
	"strings"
)

type DNSResult struct {
	HasA     bool
	HasAAAA  bool
	HasCNAME bool
	HasMX    bool
	HasNS    bool

	A     []string
	AAAA  []string
	CNAME string
	MX    []string
	NS    []string
}

// lookupDNS performs DNS lookups for A, AAAA, CNAME, MX, and NS records for a given domain
// Returns DNSResult struct and an error, prefer most informative error if multiple lookups fail
func lookupDNS(ctx context.Context, domain string) (DNSResult, error) {
	var r DNSResult

	resolver := net.DefaultResolver

	// A / AAAA
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				r.HasA = true
				r.A = append(r.A, ip.IP.String())
			} else if ip.IP.To16() != nil {
				r.HasAAAA = true
				r.AAAA = append(r.AAAA, ip.IP.String())
			}
		}
	}

	// CNAME
	cname, errC := resolver.LookupCNAME(ctx, domain)
	if errC == nil && cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), domain) {
		r.HasCNAME = true
		r.CNAME = strings.TrimSuffix(cname, ".")
	}

	// MX
	mxs, errMX := resolver.LookupMX(ctx, domain)
	if errMX == nil && len(mxs) > 0 {
		r.HasMX = true
		for _, mx := range mxs {
			r.MX = append(r.MX, strings.TrimSuffix(mx.Host, "."))
		}
	}

	// NS
	nss, errNS := resolver.LookupNS(ctx, domain)
	if errNS == nil && len(nss) > 0 {
		r.HasNS = true
		for _, ns := range nss {
			r.NS = append(r.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// Return whichever error is most meaningful;
	// DNS can fail per-record while others succeed.
	// If nothing was found and all lookups failed, return a generic error.
	if !r.HasA && !r.HasAAAA && !r.HasCNAME && !r.HasMX && !r.HasNS {
		if err != nil {
			return r, err
		}
		if errC != nil {
			return r, errC
		}
		if errMX != nil {
			return r, errMX
		}
		if errNS != nil {
			return r, errNS
		}
	}

	return r, nil
}
