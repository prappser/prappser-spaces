//go:build integration

package oauth

import (
	"crypto/x509"
	"net/netip"
)

// Test only: disables the SSRF guard.
func (s *Service) TestOnlyDisableSSRFGuard(rootCAs *x509.CertPool) {
	s.fetcher = &metadataFetcher{client: newSafeClient(func(netip.Addr) bool { return true }, rootCAs)}
}
