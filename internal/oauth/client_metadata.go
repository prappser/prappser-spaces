package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/goccy/go-json"
)

const (
	fetchTimeout   = 5 * time.Second
	maxMetadataLen = 5 * 1024
	maxClientName  = 100
)

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
	netip.MustParsePrefix("2001:db8::/32"),
}

func isPublicAddr(a netip.Addr) bool {
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

type metadataFetcher struct {
	client *http.Client
}

func newMetadataFetcher() *metadataFetcher {
	return &metadataFetcher{client: newSafeClient(isPublicAddr, nil)}
}

func newSafeClient(allow func(netip.Addr) bool, rootCAs *x509.CertPool) *http.Client {
	dialer := &net.Dialer{
		Timeout: fetchTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return errors.New("address not allowed")
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		},
	}
}

func (f *metadataFetcher) fetch(ctx context.Context, clientID string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataLen+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read client metadata: %w", err)
	}
	if len(body) > maxMetadataLen {
		return nil, errors.New("client metadata too large")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return nil, errors.New("client metadata is not a JSON object")
	}
	return doc, nil
}

func parseClientID(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") {
		return nil, errors.New("client_id is not a valid URL")
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("client_id must be an https URL")
	}
	if u.User != nil {
		return nil, errors.New("client_id must not contain credentials")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("client_id must have a path")
	}
	for _, p := range []string{u.Path, u.EscapedPath()} {
		for _, seg := range strings.Split(p, "/") {
			if seg == "." || seg == ".." {
				return nil, errors.New("client_id must not contain dot segments")
			}
		}
	}
	return u, nil
}

type clientInfo struct {
	id           string
	host         string
	name         string
	uri          string
	logoURI      string
	redirectURIs []string
}

func parseClientDoc(clientID string, doc map[string]any) (*clientInfo, error) {
	u, err := parseClientID(clientID)
	if err != nil {
		return nil, err
	}
	if id, _ := doc["client_id"].(string); id != clientID {
		return nil, errors.New("client metadata client_id does not match the URL")
	}
	if _, ok := doc["client_secret"]; ok {
		return nil, errors.New("client metadata must not contain a client_secret")
	}
	rawURIs, _ := doc["redirect_uris"].([]any)
	if len(rawURIs) == 0 {
		return nil, errors.New("client metadata has no redirect_uris")
	}
	info := &clientInfo{id: clientID, host: u.Host}
	for _, v := range rawURIs {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("redirect_uris must be strings")
		}
		info.redirectURIs = append(info.redirectURIs, s)
	}
	if !isPublicClient(doc) {
		return nil, errors.New("only public clients are supported")
	}

	name, _ := doc["client_name"].(string)
	if name = sanitizeName(name); name == "" {
		name = u.Host
	}
	info.name = name
	info.uri = httpsOnly(doc["client_uri"])
	info.logoURI = httpsOnly(doc["logo_uri"])
	return info, nil
}

func isPublicClient(doc map[string]any) bool {
	if m, _ := doc["token_endpoint_auth_method"].(string); m == "none" {
		return true
	}
	supported, _ := doc["token_endpoint_auth_methods_supported"].([]any)
	for _, v := range supported {
		if s, _ := v.(string); s == "none" {
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxClientName {
		s = strings.TrimSpace(string(r[:maxClientName]))
	}
	return s
}

func httpsOnly(v any) string {
	s, _ := v.(string)
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ""
	}
	return s
}

func isLoopbackHost(h string) bool {
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

func parseRedirectURI(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("redirect_uri is not a valid URL")
	}
	if u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return u, nil
	}
	return nil, errors.New("redirect_uri must be https or http on a loopback host")
}

func redirectMatches(requested *url.URL, raw string, registered []string) bool {
	loopback := requested.Scheme == "http"
	for _, entry := range registered {
		if entry == raw {
			return true
		}
		if !loopback {
			continue
		}
		e, err := url.Parse(entry)
		if err != nil || e.Scheme != "http" || e.User != nil || strings.Contains(entry, "#") {
			continue
		}
		if e.Hostname() == requested.Hostname() && e.Path == requested.Path && e.RawQuery == requested.RawQuery {
			return true
		}
	}
	return false
}
