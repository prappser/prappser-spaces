package status

import (
	"errors"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/spaceprofile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type fakeProfile struct {
	profile spaceprofile.Profile
	err     error
}

func (f fakeProfile) Get() (spaceprofile.Profile, error) { return f.profile, f.err }

func statusOf(t *testing.T, profile ProfileGetter) map[string]any {
	t.Helper()
	ctx := &fasthttp.RequestCtx{}
	NewEndpoints("1.0.0", 0, 0, nil, "", nil, profile).Status(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var body map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body
}

func TestStatus_ShouldIncludeTheOwnersNameAndImage(t *testing.T) {
	// given
	image := "img"

	// when
	body := statusOf(t, fakeProfile{profile: spaceprofile.Profile{Name: "Family", AvatarStorageID: &image}})

	// then
	assert.Equal(t, "Family", body["name"])
	assert.Equal(t, "img", body["avatarStorageId"])
}

func TestStatus_ShouldSendAnEmptyNameWhenUnsetOrFailing(t *testing.T) {
	for _, profile := range []ProfileGetter{fakeProfile{}, fakeProfile{err: errors.New("db down")}} {
		// when
		body := statusOf(t, profile)

		// then
		assert.Equal(t, "", body["name"])
		assert.Nil(t, body["avatarStorageId"])
		assert.Contains(t, body, "avatarStorageId")
	}
}
