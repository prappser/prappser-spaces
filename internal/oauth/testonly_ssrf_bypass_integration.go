//go:build integration

package oauth

import (
	"crypto/x509"
	"net/netip"

	"github.com/prappser/prappser-spaces/internal/netguard"
)

func (s *Service) TestOnlyDisableSSRFGuard(rootCAs *x509.CertPool) {
	s.fetcher = &metadataFetcher{client: netguard.NewClient(func(netip.Addr) bool { return true }, rootCAs, fetchTimeout, false)}
}
