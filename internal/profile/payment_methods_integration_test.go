//go:build integration

package profile

import (
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

const secretMethods = `[{"id":"cash","type":"cash","value":"","label":""},{"id":"b1","type":"blik","value":"SECRET-123","label":"Me"}]`

func getProfileBody(t *testing.T, repo user.Repository, pk string) map[string]json.RawMessage {
	t.Helper()
	u, err := repo.GetUserByPublicKey(pk)
	require.NoError(t, err)
	require.NotNil(t, u)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", u)
	user.NewEndpoints(repo, user.Config{}, nil, nil, nil, nil).GetProfile(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body
}

func patchProfile(t *testing.T, ep *ProfileEndpoints, repo user.Repository, pk, body string) *fasthttp.RequestCtx {
	t.Helper()
	u, err := repo.GetUserByPublicKey(pk)
	require.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody([]byte(body))
	ctx.SetUserValue("user", u)
	ep.UpdateProfile(ctx)
	return ctx
}

func TestPaymentMethods_ShouldRoundTripThroughPatchAndGetProfile_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := user.NewUserRepository(db)
	ep := NewProfileEndpoints(repo, application.NewRepository(db), &mockEventService{})
	const pk = "pay-pk-0123456789abcdefghij"
	testdb.InsertTestUser(t, db, pk)

	// when
	before := getProfileBody(t, repo, pk)
	patch := patchProfile(t, ep, repo, pk, `{"paymentMethods":`+secretMethods+`}`)
	afterSet := getProfileBody(t, repo, pk)
	cleared := patchProfile(t, ep, repo, pk, `{"paymentMethods":[]}`)
	afterClear := getProfileBody(t, repo, pk)
	var patchBody map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(patch.Response.Body(), &patchBody))

	// then
	assert.Contains(t, before, "paymentMethods")
	assert.Equal(t, "null", string(before["paymentMethods"]))
	assert.Equal(t, fasthttp.StatusOK, patch.Response.StatusCode())
	assert.NotContains(t, patchBody, "paymentMethods")
	assert.JSONEq(t, secretMethods, string(afterSet["paymentMethods"]))
	assert.Equal(t, fasthttp.StatusOK, cleared.Response.StatusCode())
	assert.JSONEq(t, `[]`, string(afterClear["paymentMethods"]))
}

func TestPaymentMethods_ShouldReturn400AndStoreNothingWhenDatabaseRejectsValue_Integration(t *testing.T) {
	cases := []struct{ name, pk, methods string }{
		{"numeric overflow", "pay-reject-ovf-0123456789abc", `[{"v":1e999999}]`},
		{"escaped nul", "pay-reject-nul-0123456789abc", `[{"v":"\u0000"}]`},
		{"lone surrogate", "pay-reject-sur-0123456789abc", `[{"v":"\ud800"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// given
			db := testdb.Connect(t, "profile")
			defer db.Close()
			repo := user.NewUserRepository(db)
			ep := NewProfileEndpoints(repo, application.NewRepository(db), &mockEventService{})
			testdb.InsertTestUser(t, db, tc.pk)

			// when
			ctx := patchProfile(t, ep, repo, tc.pk, `{"locale":"pl","paymentMethods":`+tc.methods+`}`)

			// then
			assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
			assert.Equal(t, "null", string(getProfileBody(t, repo, tc.pk)["paymentMethods"]))
			u, err := repo.GetUserByPublicKey(tc.pk)
			require.NoError(t, err)
			assert.NotEqual(t, "pl", u.Locale)
		})
	}
}

func TestPaymentMethods_ShouldNotBeReadableByAnotherUser_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := user.NewUserRepository(db)
	ep := NewProfileEndpoints(repo, application.NewRepository(db), &mockEventService{})
	const owner, other = "pay-owner-0123456789abcdefgh", "pay-other-0123456789abcdefgh"
	testdb.InsertTestUser(t, db, owner)
	testdb.InsertTestUser(t, db, other)
	require.Equal(t, fasthttp.StatusOK, patchProfile(t, ep, repo, owner, `{"paymentMethods":`+secretMethods+`}`).Response.StatusCode())

	// when
	otherProfile := getProfileBody(t, repo, other)

	// then
	assert.Equal(t, "null", string(otherProfile["paymentMethods"]))
	raw, err := json.Marshal(otherProfile)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SECRET-123")
}

func TestPaymentMethods_ShouldStayOutOfUserLookupMemberListAndRenameEvent_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := user.NewUserRepository(db)
	appRepo := application.NewRepository(db)
	events := &mockEventService{}
	ep := NewProfileEndpoints(repo, appRepo, events)
	const pk = "pay-leak-0123456789abcdefghi"
	testdb.InsertTestUser(t, db, pk)
	now := time.Now().Unix()
	require.NoError(t, appRepo.RegisterApplication(&application.Application{ID: "pay-app", Name: "pay-app", CreatedAt: now, UpdatedAt: now}))
	_, err := db.Exec(`INSERT INTO members (id, application_id, role, public_key) VALUES ('pay-m1','pay-app','owner',$1)`, pk)
	require.NoError(t, err)

	// when
	require.Equal(t, fasthttp.StatusOK, patchProfile(t, ep, repo, pk, `{"displayName":"Renamed","paymentMethods":`+secretMethods+`}`).Response.StatusCode())
	u, err := repo.GetUserByPublicKey(pk)
	require.NoError(t, err)
	userJSON, err := json.Marshal(u)
	require.NoError(t, err)
	members, err := appRepo.GetMembersByApplicationID("pay-app")
	require.NoError(t, err)
	memberJSON, err := json.Marshal(members)
	require.NoError(t, err)

	// then
	assert.NotContains(t, string(userJSON), "paymentMethods")
	assert.NotContains(t, string(userJSON), "SECRET-123")
	require.Len(t, members, 1)
	assert.NotContains(t, string(memberJSON), "paymentMethods")
	assert.NotContains(t, string(memberJSON), "SECRET-123")
	require.Len(t, events.produced, 1)
	eventJSON, err := json.Marshal(events.produced[0])
	require.NoError(t, err)
	assert.NotContains(t, string(eventJSON), "SECRET-123")
	assert.NotContains(t, string(eventJSON), "paymentMethods")
}
