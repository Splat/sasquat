package verify

/*
  This library is used to configure and check DNS for a given domain.
  To be used when enumerating typosquatting permutations.
*/

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type Config struct {
	DNSTimeout          time.Duration
	HTTPTimeout         time.Duration
	TLSTimeout          time.Duration
	DoTLS               bool
	DoHTTP              bool
	HTTPFollowRedirects bool
	UserAgent           string
}

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

type TLSResult struct {
	Connected    bool
	ServerName   string
	Issuer       string
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	DNSNames     []string
	CommonName   string
	SerialNumber string
	// TODO: HasRedirect 	bool
	// TODO: RedirectChain	[]string
	// TODO: Remediated 	bool
}

type HTTPResult struct {
	Attempted  bool
	URL        string
	Status     string
	StatusCode int
	Location   string
	Server     string
	// TODO: HasRedirect 	bool
	// TODO: RedirectChain	[]string
	// TODO: Remediated 	bool
}

type Verification struct {
	Domain     string
	ASCII      string // punycode/ascii form
	DNS        DNSResult
	TLS        *TLSResult
	HTTP       *HTTPResult
	Resolvable bool // TODO: double check it works to mark true is one or other is true https||http
	HasMail    bool
}

func VerifyDomain(ctx context.Context, domain string, cfg Config) (Verification, error) {
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = 2 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 4 * time.Second
	}
	if cfg.TLSTimeout <= 0 {
		cfg.TLSTimeout = 3 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "typosquat-verifier/1.0"
	}

	ascii, err := toASCII(domain)
	if err != nil {
		return Verification{}, err
	}

	v := Verification{Domain: domain, ASCII: ascii}

	dnsCtx, cancel := context.WithTimeout(ctx, cfg.DNSTimeout)
	defer cancel()

	dnsRes, err := lookupDNS(dnsCtx, ascii)
	if err != nil {
		// DNS errors are common; treat as non-fatal unless it’s a hard context error.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return Verification{}, err
		}
	}
	v.DNS = dnsRes
	v.Resolvable = dnsRes.HasA || dnsRes.HasAAAA || dnsRes.HasCNAME
	v.HasMail = dnsRes.HasMX

	if cfg.DoTLS {
		tlsCtx, cancelTLS := context.WithTimeout(ctx, cfg.TLSTimeout)
		defer cancelTLS()
		if v.Resolvable { // Only attempt TLS if it resolves
			tr := fetchTLS(tlsCtx, ascii)
			v.TLS = &tr
		}
	}

	if cfg.DoHTTP {
		httpCtx, cancelHTTP := context.WithTimeout(ctx, cfg.HTTPTimeout)
		defer cancelHTTP()
		if v.Resolvable {
			hr := fetchHTTP(httpCtx, ascii, cfg)
			v.HTTP = &hr
		}
	}

	return v, nil
}

func toASCII(domain string) (string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return "", errors.New("empty domain")
	}
	// IDNA: convert Unicode to ASCII punycode representation.
	return idna.Lookup.ToASCII(domain)
}

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

	// Return whichever error is most meaningful; DNS can fail per-record while others succeed.
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

func fetchTLS(ctx context.Context, domain string) TLSResult {
	res := TLSResult{ServerName: domain}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return res
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain, // SNI
		InsecureSkipVerify: true,   // We want metadata even for bad certs; do not use for trust decisions.
	})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return res
	}
	state := tlsConn.ConnectionState()
	res.Connected = true

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.Issuer = cert.Issuer.String()
		res.Subject = cert.Subject.String()
		res.NotBefore = cert.NotBefore
		res.NotAfter = cert.NotAfter
		res.DNSNames = append([]string{}, cert.DNSNames...)
		res.CommonName = cert.Subject.CommonName
		res.SerialNumber = cert.SerialNumber.String()
	}
	return res
}

func fetchHTTP(ctx context.Context, domain string, cfg Config) HTTPResult {
	res := HTTPResult{Attempted: true}
	target := "https://" + domain + "/"
	res.URL = target

	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}
	if !cfg.HTTPFollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", cfg.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		// If HTTPS fails, try HTTP as a fallback.
		target = "http://" + domain + "/"
		res.URL = target
		req2, err2 := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err2 != nil {
			return res
		}
		req2.Header.Set("User-Agent", cfg.UserAgent)
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return res
		}
		defer resp2.Body.Close()
		res.Status = resp2.Status
		res.StatusCode = resp2.StatusCode
		res.Location = resp2.Header.Get("Location")
		res.Server = resp2.Header.Get("Server")
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.Status
	res.StatusCode = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	res.Server = resp.Header.Get("Server")
	return res
}

// Optional helper for stronger TLS parsing later.
func parseLeafCert(_ *x509.Certificate) {
	// TODO: inspect if these leaf certs somehow match the base domain OU or something
}
