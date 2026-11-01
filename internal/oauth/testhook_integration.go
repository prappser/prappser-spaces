//go:build integration

package oauth

import (
	"crypto/x509"
	"net/netip"
)

func (s *Service) UseTestFetcher(rootCAs *x509.CertPool) {
	s.fetcher = &metadataFetcher{client: newSafeClient(func(netip.Addr) bool { return true }, rootCAs)}
}
