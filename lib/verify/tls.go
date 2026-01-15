package verify

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

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
