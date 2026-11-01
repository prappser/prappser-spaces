package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer      = "https://space.test"
	testChallenge   = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	loopbackRedir   = "http://127.0.0.1:51234/callback"
	portlessLoop    = "http://127.0.0.1/callback"
	validRedirectTo = "https://client.example/cb"
)

// docServer serves one client metadata document over TLS on loopback and
// returns a fetcher that trusts it.
func docServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *metadataFetcher) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, &metadataFetcher{client: newSafeClient(func(netip.Addr) bool { return true }, pool)}
}

func serveDoc(t *testing.T, build func(clientID string) map[string]any) (*Service, string) {
	t.Helper()
	var clientID string
	srv, fetcher := docServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(build(clientID))
	})
	clientID = srv.URL + "/client.json"
	svc := NewService(nil, nil, testIssuer, "https://app.test/")
	svc.fetcher = fetcher
	return svc, clientID
}

func goodDoc(clientID string) map[string]any {
	return map[string]any{
		"client_id":                  clientID,
		"client_name":                "Test Agent",
		"redirect_uris":              []any{validRedirectTo, portlessLoop},
		"token_endpoint_auth_method": "none",
	}
}

func baseParams(clientID string) authorizeParams {
	return authorizeParams{
		ClientID:            clientID,
		RedirectURI:         validRedirectTo,
		ResponseType:        "code",
		CodeChallenge:       testChallenge,
		CodeChallengeMethod: "S256",
		State:               "st",
	}
}

func TestIsPublicAddr_ShouldRejectNonGlobalRanges(t *testing.T) {
	// given
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "fd00::1", "169.254.169.254",
		"fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "0.1.2.3", "100.64.0.1", "192.0.0.8",
		"192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.9", "240.0.0.1", "255.255.255.255",
		"64:ff9b::808:808", "64:ff9b:1::1", "2002:808:808::1", "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "ff01::1",
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"}

	// when / then
	for _, s := range blocked {
		assert.False(t, isPublicAddr(netip.MustParseAddr(s)), s)
	}
	for _, s := range allowed {
		assert.True(t, isPublicAddr(netip.MustParseAddr(s)), s)
	}
}

func TestRedirectMatches_ShouldFollowLoopbackPortRule(t *testing.T) {
	// given
	cases := []struct {
		name       string
		requested  string
		registered []string
		want       bool
	}{
		{"exact https", "https://c.example/cb", []string{"https://c.example/cb"}, true},
		{"https port must match", "https://c.example:8443/cb", []string{"https://c.example/cb"}, false},
		{"https path mismatch", "https://c.example/other", []string{"https://c.example/cb"}, false},
		{"127.0.0.1 port ignored", loopbackRedir, []string{portlessLoop}, true},
		{"localhost port ignored", "http://localhost:3000/callback", []string{"http://localhost/callback"}, true},
		{"ipv6 port ignored", "http://[::1]:9999/callback", []string{"http://[::1]/callback"}, true},
		{"registered port ignored", portlessLoop, []string{"http://127.0.0.1:7000/callback"}, true},
		{"loopback escaped slash not decoded", "http://127.0.0.1:1234/a%2Fb", []string{"http://127.0.0.1/a/b"}, false},
		{"loopback path mismatch", "http://127.0.0.1:1/other", []string{portlessLoop}, false},
		{"loopback query mismatch", "http://127.0.0.1:1/callback?x=1", []string{portlessLoop}, false},
		{"loopback host mismatch", "http://localhost:1/callback", []string{portlessLoop}, false},
		{"https never ignores port against http", "https://127.0.0.1:1/callback", []string{portlessLoop}, false},
	}

	// when / then
	for _, c := range cases {
		u, err := parseRedirectURI(c.requested)
		require.NoError(t, err, c.name)
		assert.Equal(t, c.want, redirectMatches(u, c.requested, c.registered), c.name)
	}
}

func TestParseRedirectURI_ShouldRejectUnsafeSchemesAndShapes(t *testing.T) {
	// given
	bad := []string{
		"javascript:alert(1)", "data:text/html,x", "http://evil.example/cb", "ftp://c.example/cb",
		"https://c.example/cb#frag", "https://user:pw@c.example/cb", "/relative", "myapp://cb", "",
	}

	// when / then
	for _, raw := range bad {
		_, err := parseRedirectURI(raw)
		assert.Error(t, err, raw)
	}
}

func TestParseClientID_ShouldRejectBadShapes(t *testing.T) {
	// given
	bad := []string{
		"http://c.example/client.json", "https://c.example", "https://c.example/", "https://c.example/a#f",
		"https://u:p@c.example/a", "https://c.example/a/../b", "https://c.example/./a", "https://c.example/%2e%2e/a",
		"not a url", "",
	}

	// when / then
	for _, raw := range bad {
		_, err := parseClientID(raw)
		assert.Error(t, err, raw)
	}
	_, err := parseClientID("https://c.example/oauth/client.json?v=1")
	assert.NoError(t, err)
}

func TestParseClientDoc_ShouldValidateDocument(t *testing.T) {
	// given
	id := "https://c.example/client.json"
	with := func(mutate func(d map[string]any)) map[string]any {
		d := goodDoc(id)
		mutate(d)
		return d
	}

	// when / then
	_, err := parseClientDoc(id, with(func(d map[string]any) { d["client_id"] = "https://c.example/other" }))
	assert.Error(t, err, "client_id mismatch")
	_, err = parseClientDoc(id, with(func(d map[string]any) { d["client_secret"] = "x" }))
	assert.Error(t, err, "client_secret present")
	_, err = parseClientDoc(id, with(func(d map[string]any) { d["redirect_uris"] = []any{} }))
	assert.Error(t, err, "empty redirect_uris")
	_, err = parseClientDoc(id, with(func(d map[string]any) { d["redirect_uris"] = []any{1} }))
	assert.Error(t, err, "non-string redirect_uri")
	_, err = parseClientDoc(id, with(func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_basic" }))
	assert.Error(t, err, "confidential client")
	_, err = parseClientDoc(id, with(func(d map[string]any) { delete(d, "token_endpoint_auth_method") }))
	assert.Error(t, err, "no auth method")
}

func TestParseClientDoc_ChatGPTStyleDoc_ShouldBeAccepted(t *testing.T) {
	// given
	id := "https://c.example/client.json"
	doc := map[string]any{
		"client_id":                             id,
		"redirect_uris":                         []any{validRedirectTo},
		"token_endpoint_auth_method":            "private_key_jwt",
		"token_endpoint_auth_methods_supported": []any{"private_key_jwt", "none"},
	}

	// when
	info, err := parseClientDoc(id, doc)

	// then
	require.NoError(t, err)
	assert.Equal(t, "c.example", info.name)
}

func TestParseClientDoc_ShouldSanitizeNameAndDropNonHTTPSLinks(t *testing.T) {
	// given
	id := "https://c.example/client.json"
	doc := goodDoc(id)
	doc["client_name"] = "  \x00Evil\nName" + strings.Repeat("x", 200)
	doc["client_uri"] = "http://c.example"
	doc["logo_uri"] = "https://c.example/logo.png"

	// when
	info, err := parseClientDoc(id, doc)

	// then
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(info.name, "EvilNamexxx"))
	assert.Len(t, []rune(info.name), 100)
	assert.Empty(t, info.uri)
	assert.Equal(t, "https://c.example/logo.png", info.logoURI)
}

func TestFetch_ShouldReturnDocument(t *testing.T) {
	// given
	srv, fetcher := docServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"client_id":"x"}`))
	})

	// when
	doc, err := fetcher.fetch(context.Background(), srv.URL+"/c.json")

	// then
	require.NoError(t, err)
	assert.Equal(t, "x", doc["client_id"])
}

func TestFetch_ShouldRefuseRedirectNon200TooLargeAndNonObject(t *testing.T) {
	// given
	srv, fetcher := docServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/missing":
			http.NotFound(w, r)
		case "/big":
			_, _ = w.Write([]byte(`{"a":"` + strings.Repeat("x", 6*1024) + `"}`))
		case "/array":
			_, _ = w.Write([]byte(`[1]`))
		case "/null":
			_, _ = w.Write([]byte(`null`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	})

	// when / then
	for _, p := range []string{"/redirect", "/missing", "/big", "/array", "/null"} {
		_, err := fetcher.fetch(context.Background(), srv.URL+p)
		assert.Error(t, err, p)
	}
}

func TestFetch_Production_ShouldRefuseLoopback(t *testing.T) {
	// given
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// when
	_, err := newMetadataFetcher().fetch(context.Background(), srv.URL+"/c.json")

	// then
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address not allowed")
}

func TestPKCEMatches_ShouldVerifyS256(t *testing.T) {
	// given / when / then
	assert.True(t, pkceMatches(testVerifier, testChallenge))
	assert.False(t, pkceMatches(testVerifier+"x", testChallenge))
	assert.True(t, validVerifier(testVerifier))
	assert.False(t, validVerifier(strings.Repeat("a", 42)))
	assert.False(t, validVerifier(strings.Repeat("a", 129)))
	assert.False(t, validVerifier(strings.Repeat("a", 42)+"!"))
	assert.True(t, validChallenge(testChallenge))
	assert.False(t, validChallenge(testChallenge+"="))
	sum := sha256.Sum256([]byte(testVerifier))
	assert.Equal(t, testChallenge, base64.RawURLEncoding.EncodeToString(sum[:]))
}

func TestAuthorize_ValidRequest_ShouldReturnConsentURL(t *testing.T) {
	// given
	svc, clientID := serveDoc(t, goodDoc)
	p := baseParams(clientID)

	// when
	got, err := svc.Authorize(context.Background(), p)

	// then
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(got, "https://app.test/#/oauth/consent?space=https%3A%2F%2Fspace.test&request="), got)
}

func TestAuthorize_ResourceAndScope_ShouldFollowRules(t *testing.T) {
	// given
	svc, clientID := serveDoc(t, goodDoc)
	check := func(mutate func(p *authorizeParams)) error {
		p := baseParams(clientID)
		mutate(&p)
		_, err := svc.Authorize(context.Background(), p)
		return err
	}
	code := func(err error) string {
		var e *Error
		require.ErrorAs(t, err, &e)
		return e.Code
	}

	// when / then
	assert.NoError(t, check(func(p *authorizeParams) {}), "resource absent")
	assert.NoError(t, check(func(p *authorizeParams) { p.Resource, p.HasResource = testIssuer+"/mcp", true }))
	assert.Equal(t, CodeInvalidTarget, code(check(func(p *authorizeParams) { p.Resource, p.HasResource = "https://other.test/mcp", true })))
	assert.Equal(t, CodeInvalidTarget, code(check(func(p *authorizeParams) { p.HasResource = true })))
	assert.NoError(t, check(func(p *authorizeParams) { p.Scope = "mcp offline_access" }))
	assert.Equal(t, CodeInvalidScope, code(check(func(p *authorizeParams) { p.Scope = "mcp admin" })))
}

func TestAuthorize_BadParams_ShouldBeRejected(t *testing.T) {
	// given
	svc, clientID := serveDoc(t, goodDoc)
	bad := map[string]func(p *authorizeParams){
		"plain method":      func(p *authorizeParams) { p.CodeChallengeMethod = "plain" },
		"missing method":    func(p *authorizeParams) { p.CodeChallengeMethod = "" },
		"short challenge":   func(p *authorizeParams) { p.CodeChallenge = "abc" },
		"token response":    func(p *authorizeParams) { p.ResponseType = "token" },
		"unregistered uri":  func(p *authorizeParams) { p.RedirectURI = "https://evil.example/cb" },
		"http non-loopback": func(p *authorizeParams) { p.RedirectURI = "http://client.example/cb" },
		"bad client id":     func(p *authorizeParams) { p.ClientID = "http://c.example/x" },
	}

	// when / then
	for name, mutate := range bad {
		p := baseParams(clientID)
		mutate(&p)
		_, err := svc.Authorize(context.Background(), p)
		var e *Error
		assert.ErrorAs(t, err, &e, name)
	}
}

func TestAuthorize_LoopbackRedirectWithRandomPort_ShouldBeAccepted(t *testing.T) {
	// given
	svc, clientID := serveDoc(t, goodDoc)
	p := baseParams(clientID)
	p.RedirectURI = loopbackRedir

	// when
	_, err := svc.Authorize(context.Background(), p)

	// then
	assert.NoError(t, err)
}

func TestAuthorize_FullStore_ShouldReturnErrStoreFull(t *testing.T) {
	// given
	svc, clientID := serveDoc(t, goodDoc)
	for i := 0; i < maxPending; i++ {
		_, err := svc.store.addPending(&pendingRequest{clientID: strconv.Itoa(i)})
		require.NoError(t, err)
	}

	// when
	_, err := svc.Authorize(context.Background(), baseParams(clientID))

	// then
	assert.ErrorIs(t, err, ErrStoreFull)
}

func TestStore_Pending_ShouldBindToFirstAuthenticatedReaderAndExpire(t *testing.T) {
	// given
	s := newStore()
	id, err := s.addPending(&pendingRequest{redirectURI: "x"})
	require.NoError(t, err)

	// when
	_, errFirst := s.getPending(id, "alice")
	_, errOther := s.getPending(id, "bob")
	_, errTakeOther := s.takePending(id, "bob")
	_, errTake := s.takePending(id, "alice")
	_, errGone := s.getPending(id, "alice")

	// then
	assert.NoError(t, errFirst)
	assert.ErrorIs(t, errOther, ErrWrongUser)
	assert.ErrorIs(t, errTakeOther, ErrWrongUser)
	assert.NoError(t, errTake)
	assert.ErrorIs(t, errGone, ErrRequestNotFound)
}

func TestStore_AddPending_ShouldEvictOldestOfSameClientAndIPAtCap(t *testing.T) {
	// given
	s := newStore()
	first, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
	require.NoError(t, err)
	other, err := s.addPending(&pendingRequest{clientID: "b", sourceIP: "ip-a"})
	require.NoError(t, err)
	orig := nowFunc
	n := 0
	nowFunc = func() time.Time { n++; return orig().Add(time.Duration(n) * time.Second) }
	defer func() { nowFunc = orig }()
	var last string
	for i := 1; i < maxPendingPerClientIP+1; i++ {
		last, err = s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
		require.NoError(t, err)
	}

	// when
	_, errFirst := s.getPending(first, "u")
	_, errLast := s.getPending(last, "u")
	_, errOther := s.getPending(other, "u")

	// then
	assert.ErrorIs(t, errFirst, ErrRequestNotFound)
	assert.NoError(t, errLast)
	assert.NoError(t, errOther)
}

func TestStore_AddPending_ShouldNotEvictAnotherIPsRequestsOfSameClient(t *testing.T) {
	// given
	s := newStore()
	orig := nowFunc
	n := 0
	nowFunc = func() time.Time { n++; return orig().Add(time.Duration(n) * time.Second) }
	defer func() { nowFunc = orig }()
	var idsA, idsB []string
	for i := 0; i < maxPendingPerClientIP; i++ {
		id, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
		require.NoError(t, err)
		idsA = append(idsA, id)
	}
	for i := 0; i < maxPendingPerClientIP; i++ {
		id, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-b"})
		require.NoError(t, err)
		idsB = append(idsB, id)
	}
	for _, id := range append(append([]string{}, idsA...), idsB...) {
		_, err := s.lookupPending(id, "")
		require.NoError(t, err)
	}

	// when
	extra, errExtra := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-b"})
	_, errOldestB := s.lookupPending(idsB[0], "")
	_, errNextB := s.lookupPending(idsB[1], "")
	_, errExtraGet := s.lookupPending(extra, "")

	// then
	assert.NoError(t, errExtra)
	assert.ErrorIs(t, errOldestB, ErrRequestNotFound)
	assert.NoError(t, errNextB)
	assert.NoError(t, errExtraGet)
	for _, id := range idsA {
		_, err := s.lookupPending(id, "")
		assert.NoError(t, err)
	}
}

func TestStore_AddPending_ShouldKeepRequestsAUserAlreadyOpened(t *testing.T) {
	// given
	s := newStore()
	orig := nowFunc
	n := 0
	nowFunc = func() time.Time { n++; return orig().Add(time.Duration(n) * time.Second) }
	defer func() { nowFunc = orig }()
	ids := make([]string, 0, maxPendingPerClientIP)
	for i := 0; i < maxPendingPerClientIP; i++ {
		id, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
		require.NoError(t, err)
		ids = append(ids, id)
	}
	_, err := s.getPending(ids[0], "user-a")
	require.NoError(t, err)

	// when
	extra, errExtra := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
	_, errBound := s.getPending(ids[0], "user-a")
	_, errSecond := s.getPending(ids[1], "user-b")
	_, errNew := s.getPending(extra, "user-b")

	// then
	assert.NoError(t, errExtra)
	assert.NoError(t, errBound)
	assert.ErrorIs(t, errSecond, ErrRequestNotFound)
	assert.NoError(t, errNew)
}

func TestStore_AddPending_ShouldReturnStoreFullWhenEveryClientIPRequestIsOpened(t *testing.T) {
	// given
	s := newStore()
	for i := 0; i < maxPendingPerClientIP; i++ {
		id, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
		require.NoError(t, err)
		_, err = s.getPending(id, "user-a")
		require.NoError(t, err)
	}

	// when
	_, err := s.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})

	// then
	assert.ErrorIs(t, err, ErrStoreFull)
}

func TestStore_UnmarkCode_ShouldNotReviveCodeAfterReuseWasSeen(t *testing.T) {
	// given
	s := newStore()
	code, err := s.addCode(&authCode{clientID: "c"})
	require.NoError(t, err)
	_, reused1, _ := s.consumeCode(code)
	_, reused2, _ := s.consumeCode(code)

	// when
	s.unmarkCode(code)
	_, reused3, found3 := s.consumeCode(code)

	// then
	assert.False(t, reused1)
	assert.True(t, reused2)
	assert.True(t, found3)
	assert.True(t, reused3)
}

func TestApprove_ExpiredRequest_ShouldReturnNotFoundWithoutTouchingAgents(t *testing.T) {
	// given
	svc := NewService(nil, nil, testIssuer, "https://app.test")
	id, err := svc.store.addPending(&pendingRequest{clientID: "a", sourceIP: "ip-a"})
	require.NoError(t, err)
	svc.store.pending[id].expiresAt = time.Now().Add(-time.Second)

	// when
	_, err = svc.Approve(id, "u")

	// then
	assert.ErrorIs(t, err, ErrRequestNotFound)
}

func TestStore_Codes_ShouldBeSingleUseAndExpire(t *testing.T) {
	// given
	s := newStore()
	code, err := s.addCode(&authCode{clientID: "c"})
	require.NoError(t, err)

	// when
	_, reused1, found1 := s.consumeCode(code)
	_, reused2, found2 := s.consumeCode(code)
	_, _, foundUnknown := s.consumeCode("nope")
	orig := nowFunc
	nowFunc = func() time.Time { return orig().Add(2 * codeTTL) }
	defer func() { nowFunc = orig }()
	_, _, foundExpired := s.consumeCode(code)

	// then
	assert.True(t, found1)
	assert.False(t, reused1)
	assert.True(t, found2)
	assert.True(t, reused2)
	assert.False(t, foundUnknown)
	assert.False(t, foundExpired)
}

func TestRedirectURL_ShouldAppendParams(t *testing.T) {
	// given
	svc := NewService(nil, nil, testIssuer, "")

	// when
	plain := svc.redirectURL(pendingRequest{redirectURI: validRedirectTo, state: "a b"}, map[string][]string{"code": {"c1"}})
	withQuery := svc.redirectURL(pendingRequest{redirectURI: validRedirectTo + "?x=1"}, map[string][]string{"error": {"access_denied"}})

	// then
	assert.Equal(t, validRedirectTo+"?code=c1&iss=https%3A%2F%2Fspace.test&state=a+b", plain)
	assert.Equal(t, validRedirectTo+"?x=1&error=access_denied&iss=https%3A%2F%2Fspace.test", withQuery)
}

func TestToken_UnknownOrMissingGrantType_ShouldReturnOAuthErrors(t *testing.T) {
	// given
	svc := NewService(nil, nil, testIssuer, "")

	// when
	_, errUnknown := svc.Token(tokenParams{GrantType: "password"})
	_, errMissing := svc.Token(tokenParams{})
	_, errNoParams := svc.Token(tokenParams{GrantType: "authorization_code"})
	_, errNoRefresh := svc.Token(tokenParams{GrantType: "refresh_token"})

	// then
	var e *Error
	require.ErrorAs(t, errUnknown, &e)
	assert.Equal(t, CodeUnsupportedGrantType, e.Code)
	require.ErrorAs(t, errMissing, &e)
	assert.Equal(t, CodeInvalidRequest, e.Code)
	require.ErrorAs(t, errNoParams, &e)
	assert.Equal(t, CodeInvalidRequest, e.Code)
	require.ErrorAs(t, errNoRefresh, &e)
	assert.Equal(t, CodeInvalidRequest, e.Code)
}
