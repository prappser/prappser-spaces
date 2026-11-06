package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

var ErrAddressNotAllowed = errors.New("address not allowed")

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// NewClient returns a client that only connects to addresses allow accepts, checked on the resolved IP at dial time.
// keepAlives is safe to enable because the dial check runs on every new connection and a reused one was already checked.
func NewClient(allow func(netip.Addr) bool, rootCAs *x509.CertPool, timeout time.Duration, keepAlives bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return ErrAddressNotAllowed
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: !keepAlives,
			// a hand-built Transport has no DefaultTransport limits; hosts are user-supplied, so bound idle conns
			IdleConnTimeout: 90 * time.Second,
			MaxIdleConns:    100,
			TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		},
	}
}
