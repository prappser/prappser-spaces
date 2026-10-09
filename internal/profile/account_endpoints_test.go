package profile

import (
	"context"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type mockBlobDeleter struct {
	calls []string
	err   error
}

func (m *mockBlobDeleter) DeletePersonalBlobs(ctx context.Context, publicKey string) error {
	m.calls = append(m.calls, publicKey)
	return m.err
}

func TestDeleteAccount_ShouldReturn409AndKeepBlobsWhenCallerIsSpaceOwner(t *testing.T) {
	// given
	blobs := &mockBlobDeleter{}
	events := &mockEventService{}
	ep := NewAccountEndpoints(nil, &mockAppLister{}, events, blobs)
	ctx := newTestRequestCtx("DELETE", "")
	setAuthUser(ctx, &user.User{PublicKey: "pk-owner", Role: user.RoleOwner})

	// when
	ep.DeleteAccount(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	var body map[string]string
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, "space_owner", body["code"])
	assert.Empty(t, blobs.calls)
	assert.Empty(t, events.produced)
}
