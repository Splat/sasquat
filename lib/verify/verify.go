package verify

/*
  This library is used to configure and check DNS for a given domain.
  To be used when enumerating typosquatting permutations.
*/

import (
	"context"
	"crypto/x509"
	"errors"
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

type Verification struct {
	Domain     string
	ASCII      string // punycode/ascii form
	DNS        DNSResult
	TLS        *TLSResult
	HTTP       *HTTPResult
	Resolvable bool
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
		cfg.UserAgent = "sasquat-verifier/1.0"
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
			hr := fetchHTTP(httpCtx, true, ascii, cfg)
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

func getTargetDomain(https bool, domain string) string {
	if https {
		return "https://" + domain + "/"
	} else {
		return "http://" + domain + "/"
	}
}

// TODO: Optional helper for stronger TLS parsing later.
func parseLeafCert(_ *x509.Certificate) {
	// TODO: inspect if these leaf certs somehow match the base domain OU or something
}
