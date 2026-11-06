package push

import (
	"net/netip"

	"github.com/prappser/prappser-spaces/internal/netguard"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

var metadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::/64"),
	netip.MustParsePrefix("100.100.100.200/32"),
}

// allowPrivateAddr is the policy for PUSH_ALLOW_PRIVATE_ENDPOINTS: a LAN-only push server (self-hosted ntfy)
// is reachable, while link-local and non-link-local cloud metadata addresses (AWS IPv6 IMDS, Alibaba), multicast
// and the other special ranges stay blocked.
func allowPrivateAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range metadataPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return a.IsLoopback() || a.IsPrivate() || cgnat.Contains(a) || netguard.IsPublic(a)
}
