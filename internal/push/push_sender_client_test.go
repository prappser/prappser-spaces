package push

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowPrivateAddr_ShouldAllowLanButNotMetadataOrMulticast(t *testing.T) {
	// given
	allowed := []string{"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1", "100.64.0.1", "::ffff:192.168.1.1", "8.8.8.8"}
	blocked := []string{"169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "255.255.255.255", "fd00:ec2::254", "100.100.100.200"}

	// when / then
	for _, s := range allowed {
		assert.True(t, allowPrivateAddr(netip.MustParseAddr(s)), s)
	}
	for _, s := range blocked {
		assert.False(t, allowPrivateAddr(netip.MustParseAddr(s)), s)
	}
}
