package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// bindingTestRepo is an in-memory stand-in for the binding-related slice of
// UserRepository. AcceptBinding mirrors the SQL ordering and escrow guards.
// The embedded nil interface panics on any method the tests do not expect.
type bindingTestRepo struct {
	UserRepository
	escrow  string
	binding string
	iat     int64
	sub     string
	devices map[string]*Device
	acct    string
}

func (r *bindingTestRepo) GetUserByPublicKey(key string) (*User, error) {
	if key != r.acct {
		return nil, nil
	}
	return &User{PublicKey: key, Username: "alice", Role: RoleUser, BindingIat: r.iat, BindingSub: r.sub, StoredBinding: r.binding}, nil
}

func (r *bindingTestRepo) TouchDeviceLastSeen(string, int64) error { return nil }

func (r *bindingTestRepo) ReviveDevice(device, account string, before int64) (bool, error) {
	d := r.devices[device]
	if d == nil || d.UserPublicKey != account || d.RevokedAt == nil || *d.RevokedAt >= before {
		return false, nil
	}
	d.RevokedAt = nil
	return true, nil
}

func (r *bindingTestRepo) GetEscrow(string) (string, string, error) { return r.escrow, "", nil }

func (r *bindingTestRepo) GetPasswordCredential(string) (string, string, error) { return "", "", nil }

func (r *bindingTestRepo) AcceptBinding(_, binding string, iat int64, sub, ownKey string) (string, string, bool, error) {
	newer := iat > r.iat || (iat == r.iat && sub > r.sub)
	if !newer || (sub == ownKey && r.escrow == "") {
		return r.binding, r.sub, false, nil
	}
	r.binding, r.iat, r.sub = binding, iat, sub
	if sub != ownKey {
		r.escrow = ""
	}
	return binding, sub, true, nil
}

func (r *bindingTestRepo) GetDevice(key string) (*Device, error) { return r.devices[key], nil }

func (r *bindingTestRepo) EnsureDevice(deviceKey, userKey string, _ *string, createdAt int64) error {
	if r.devices == nil {
		r.devices = map[string]*Device{}
	}
	r.devices[deviceKey] = &Device{DevicePublicKey: deviceKey, UserPublicKey: userKey, CreatedAt: createdAt}
	return nil
}

func newTestKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func buildBindingJWS(t *testing.T, signKey ed25519.PrivateKey, typ, iss, sub string, iat int64) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"typ": typ, "iss": iss, "sub": sub, "url": "https://space.test", "iat": iat,
	}).SignedString(signKey)
	assert.NoError(t, err)
	return signed
}

func TestVerifyBinding_ShouldAcceptValidBinding(t *testing.T) {
	// given
	priv, acct := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, priv, bindingTyp, acct, space, now.Unix())

	// when
	c, err := verifyBinding(jws, acct, now)

	// then
	assert.NoError(t, err)
	assert.Equal(t, space, c.Subject)
	assert.Equal(t, acct, c.Issuer)
	assert.Equal(t, now.Unix(), c.IssuedAt)
}

func TestVerifyBinding_ShouldRejectWrongSigner(t *testing.T) {
	// given
	_, acct := newTestKey(t)
	otherPriv, _ := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, otherPriv, bindingTyp, acct, space, now.Unix())

	// when
	_, err := verifyBinding(jws, acct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestVerifyBinding_ShouldRejectWrongTyp(t *testing.T) {
	// given
	priv, acct := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, priv, "something-else", acct, space, now.Unix())

	// when
	_, err := verifyBinding(jws, acct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestVerifyBinding_ShouldRejectIssuerThatIsNotTheAccount(t *testing.T) {
	// given
	priv, acct := newTestKey(t)
	_, space := newTestKey(t)
	_, otherAcct := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, priv, bindingTyp, acct, space, now.Unix())

	// when
	_, err := verifyBinding(jws, otherAcct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestVerifyBinding_ShouldRejectFutureIatBeyondSkew(t *testing.T) {
	// given
	priv, acct := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, priv, bindingTyp, acct, space, now.Unix()+bindingSkewSec+5)

	// when
	_, err := verifyBinding(jws, acct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestVerifyBinding_ShouldRejectMalformedSubject(t *testing.T) {
	// given
	priv, acct := newTestKey(t)
	now := time.Now()
	jws := buildBindingJWS(t, priv, bindingTyp, acct, "not-a-key", now.Unix())

	// when
	_, err := verifyBinding(jws, acct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestVerifyBinding_ShouldRejectNonCanonicalSubjectEncoding(t *testing.T) {
	// given: the same 32 bytes as a valid key, with the unused trailing bits of the last data char set
	priv, acct := newTestKey(t)
	_, sub := newTestKey(t)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alphabet, sub[42])
	nonCanonical := sub[:42] + string(alphabet[i|3]) + sub[43:]
	if nonCanonical == sub {
		nonCanonical = sub[:42] + string(alphabet[i&^3]) + sub[43:]
	}
	now := time.Now()
	jws := buildBindingJWS(t, priv, bindingTyp, acct, nonCanonical, now.Unix())

	// when
	_, err := verifyBinding(jws, acct, now)

	// then
	assert.ErrorIs(t, err, ErrInvalidBinding)
}

func TestBindingsAccept_ShouldDisconnectOnlyWhenStored(t *testing.T) {
	// given
	_, acct := newTestKey(t)
	_, space := newTestKey(t)
	_, foreign := newTestKey(t)
	repo := &bindingTestRepo{escrow: "blob"}
	b := NewBindings(repo, space)
	var disconnected [][2]string
	b.Disconnect = func(account, device string) { disconnected = append(disconnected, [2]string{account, device}) }
	c := &bindingClaims{Subject: foreign, IssuedAt: 100}

	// when
	_, _, err1 := b.Accept(acct, "jws-1", c)
	_, _, err2 := b.Accept(acct, "jws-1", c)

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, [][2]string{{acct, ""}}, disconnected)
}

func TestIsIdentitySpace_ShouldRequireEscrowAndNoForeignBinding(t *testing.T) {
	// given
	_, space := newTestKey(t)
	_, foreign := newTestKey(t)
	cases := []struct {
		name   string
		escrow string
		sub    string
		want   bool
	}{
		{"escrow, no binding", "blob", "", true},
		{"escrow, own sub", "blob", space, true},
		{"escrow, foreign sub", "blob", foreign, false},
		{"no escrow, no binding", "", "", false},
		{"no escrow, own sub", "", space, false},
	}
	for _, tc := range cases {
		b := NewBindings(&bindingTestRepo{escrow: tc.escrow}, space)

		// when
		got, err := b.IsIdentitySpace(&User{PublicKey: "acct", BindingSub: tc.sub})

		// then
		assert.NoError(t, err, tc.name)
		assert.Equal(t, tc.want, got, tc.name)
	}
}

func TestRosterAllowed_ShouldAllowAccountKeyDeviceAndLegacyAccountsButNotForeignBound(t *testing.T) {
	// given
	_, space := newTestKey(t)
	_, foreign := newTestKey(t)
	repo := &bindingTestRepo{escrow: "blob"}
	b := NewBindings(repo, space)
	bound := &User{PublicKey: "acct", BindingIat: 5, BindingSub: foreign}
	legacy := &User{PublicKey: "acct"}
	other := &Device{DevicePublicKey: "dev", UserPublicKey: "acct"}
	own := &Device{DevicePublicKey: "acct", UserPublicKey: "acct"}
	revoked := &Device{DevicePublicKey: "dev", UserPublicKey: "acct", RevokedAt: new(int64)}
	stranger := &Device{DevicePublicKey: "dev", UserPublicKey: "someone-else"}

	// when / then
	ok, _ := b.RosterAllowed(bound, own)
	assert.True(t, ok, "account-key device always passes")
	ok, _ = b.RosterAllowed(bound, other)
	assert.False(t, ok, "foreign-bound account, non-account-key device")
	ok, _ = b.RosterAllowed(legacy, other)
	assert.True(t, ok, "no binding yet")
	ok, _ = b.RosterAllowed(legacy, revoked)
	assert.False(t, ok, "revoked")
	ok, _ = b.RosterAllowed(legacy, stranger)
	assert.False(t, ok, "other account's device")
	ok, _ = b.RosterAllowed(legacy, nil)
	assert.False(t, ok, "no row")
}

func TestVerifyAdmission_ShouldAcceptAssertionFromBindingSubject(t *testing.T) {
	// given
	acctPriv, acct := newTestKey(t)
	subjPriv, subj := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	binding := buildBindingJWS(t, acctPriv, bindingTyp, acct, subj, now.Unix())
	assertion, _, err := mintAssertion(subjPriv, subj, acct, space, "alice", "dev", now)
	assert.NoError(t, err)
	b := NewBindings(&bindingTestRepo{}, space)

	// when
	c, err := b.VerifyAdmission(acct, "dev", binding, assertion, now)

	// then
	assert.NoError(t, err)
	assert.Equal(t, subj, c.claims.Subject)
	assert.Equal(t, now.Unix(), c.assertedAt)
}

func TestVerifyAdmission_ShouldRejectAssertionFromOtherIssuerOrForOtherAccount(t *testing.T) {
	// given
	acctPriv, acct := newTestKey(t)
	_, subj := newTestKey(t)
	otherPriv, other := newTestKey(t)
	subjPriv2, _ := newTestKey(t)
	_, space := newTestKey(t)
	now := time.Now()
	binding := buildBindingJWS(t, acctPriv, bindingTyp, acct, subj, now.Unix())
	b := NewBindings(&bindingTestRepo{}, space)
	fromOther, _, _ := mintAssertion(otherPriv, other, acct, space, "alice", "dev", now)
	forOther, _, _ := mintAssertion(subjPriv2, subj, "someone-else", space, "alice", "dev", now)

	// when
	_, err1 := b.VerifyAdmission(acct, "dev", binding, fromOther, now)
	_, err2 := b.VerifyAdmission(acct, "dev", binding, forOther, now)
	_, err3 := b.VerifyAdmission(acct, "dev", "garbage", fromOther, now)

	// then
	assert.ErrorIs(t, err1, ErrInvalidAssertion)
	assert.ErrorIs(t, err2, ErrInvalidAssertion)
	assert.ErrorIs(t, err3, ErrInvalidBinding)
}

func TestAdmit_ShouldRegisterNewDeviceAndReportBindingRequiredForLowerBinding(t *testing.T) {
	// given
	_, space := newTestKey(t)
	_, subjA := newTestKey(t)
	_, subjB := newTestKey(t)
	repo := &bindingTestRepo{escrow: "blob"}
	b := NewBindings(repo, space)
	now := time.Now()

	// when
	errHigh := b.Admit("acct", "dev-1", "jws-high", &Admission{claims: &bindingClaims{Subject: subjA, IssuedAt: 200}}, nil, now)
	errLow := b.Admit("acct", "dev-2", "jws-low", &Admission{claims: &bindingClaims{Subject: subjB, IssuedAt: 100}}, nil, now)

	// then
	assert.NoError(t, errHigh)
	assert.NotNil(t, repo.devices["dev-1"])
	var required *BindingRequiredError
	assert.ErrorAs(t, errLow, &required)
	assert.Equal(t, "jws-high", required.Binding)
	assert.Nil(t, repo.devices["dev-2"])
}

func TestAdmit_ShouldRejectDeviceRowOfAnotherAccount(t *testing.T) {
	// given
	_, space := newTestKey(t)
	_, subj := newTestKey(t)
	repo := &bindingTestRepo{devices: map[string]*Device{
		"theirs": {DevicePublicKey: "theirs", UserPublicKey: "other"},
		"ours":   {DevicePublicKey: "ours", UserPublicKey: "acct"},
	}}
	b := NewBindings(repo, space)
	adm := &Admission{claims: &bindingClaims{Subject: subj, IssuedAt: 100}, assertedAt: 100}

	// when
	errTheirs := b.Admit("acct", "theirs", "jws", adm, nil, time.Now())
	errOurs := b.Admit("acct", "ours", "jws", adm, nil, time.Now())

	// then
	assert.ErrorIs(t, errTheirs, ErrDeviceRowConflict)
	assert.NoError(t, errOurs)
}

func TestAdmit_ShouldReviveRevokedRowOnlyWhenAssertionIsNewerThanRevocation(t *testing.T) {
	// given
	_, space := newTestKey(t)
	_, subj := newTestKey(t)
	revokedAt := int64(1000)
	repo := &bindingTestRepo{devices: map[string]*Device{
		"newer": {DevicePublicKey: "newer", UserPublicKey: "acct", RevokedAt: &revokedAt},
		"older": {DevicePublicKey: "older", UserPublicKey: "acct", RevokedAt: &revokedAt},
		"equal": {DevicePublicKey: "equal", UserPublicKey: "acct", RevokedAt: &revokedAt},
	}}
	b := NewBindings(repo, space)
	claims := &bindingClaims{Subject: subj, IssuedAt: 100}

	// when
	errNewer := b.Admit("acct", "newer", "jws", &Admission{claims: claims, assertedAt: 1001}, nil, time.Now())
	errOlder := b.Admit("acct", "older", "jws", &Admission{claims: claims, assertedAt: 999}, nil, time.Now())
	errEqual := b.Admit("acct", "equal", "jws", &Admission{claims: claims, assertedAt: 1000}, nil, time.Now())

	// then
	assert.NoError(t, errNewer)
	assert.Nil(t, repo.devices["newer"].RevokedAt)
	assert.ErrorIs(t, errOlder, ErrDeviceRowConflict)
	assert.ErrorIs(t, errEqual, ErrDeviceRowConflict)
	assert.NotNil(t, repo.devices["older"].RevokedAt)
}

func newPutBindingCtx(t *testing.T, u *User, binding string) *fasthttp.RequestCtx {
	t.Helper()
	body, err := json.Marshal(putBindingRequest{Binding: binding})
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetBody(body)
	ctx.SetUserValue("user", u)
	return ctx
}

func TestPutBinding_ShouldReturnStoredBinding(t *testing.T) {
	// given
	acctPriv, acct := newTestKey(t)
	_, space := newTestKey(t)
	_, foreign := newTestKey(t)
	repo := &bindingTestRepo{escrow: "blob"}
	ae := NewAssertionEndpoints(repo, nil, space, NewBindings(repo, space))
	now := time.Now().Unix()
	high := buildBindingJWS(t, acctPriv, bindingTyp, acct, foreign, now)
	low := buildBindingJWS(t, acctPriv, bindingTyp, acct, foreign, now-100)
	u := &User{PublicKey: acct}

	// when
	ctxHigh := newPutBindingCtx(t, u, high)
	ae.PutBinding(ctxHigh)
	ctxLow := newPutBindingCtx(t, u, low)
	ae.PutBinding(ctxLow)

	// then
	for _, ctx := range []*fasthttp.RequestCtx{ctxHigh, ctxLow} {
		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
		var resp bindingResponse
		assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
		assert.Equal(t, high, resp.Binding)
	}
}

func TestPutBinding_ShouldReturn409NoEscrowForOwnKeyWithoutEscrow(t *testing.T) {
	// given
	acctPriv, acct := newTestKey(t)
	_, space := newTestKey(t)
	repo := &bindingTestRepo{}
	ae := NewAssertionEndpoints(repo, nil, space, NewBindings(repo, space))
	jws := buildBindingJWS(t, acctPriv, bindingTyp, acct, space, time.Now().Unix())
	ctx := newPutBindingCtx(t, &User{PublicKey: acct}, jws)

	// when
	ae.PutBinding(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.JSONEq(t, `{"code":"no_escrow"}`, string(ctx.Response.Body()))
	assert.Empty(t, repo.binding)
}

func TestPutBinding_ShouldReturn400ForInvalidBinding(t *testing.T) {
	// given
	_, acct := newTestKey(t)
	_, space := newTestKey(t)
	repo := &bindingTestRepo{escrow: "blob"}
	ae := NewAssertionEndpoints(repo, nil, space, NewBindings(repo, space))
	ctx := newPutBindingCtx(t, &User{PublicKey: acct}, "garbage")

	// when
	ae.PutBinding(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestGetProfile_ShouldExposeIdentityBindingOnlyThere(t *testing.T) {
	// given
	ue := UserEndpoints{userRepository: &bindingTestRepo{}}
	u := &User{PublicKey: "acct", Username: "alice", StoredBinding: "stored-jws"}
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", u)

	// when
	ue.GetProfile(ctx)
	plain, err := json.Marshal(u)

	// then
	assert.NoError(t, err)
	assert.Contains(t, string(ctx.Response.Body()), `"identityBinding":"stored-jws"`)
	assert.NotContains(t, string(plain), "identityBinding")
	assert.NotContains(t, string(plain), "stored-jws")
}
