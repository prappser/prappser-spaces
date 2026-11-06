package profile

import (
	"context"
	"fmt"
	"testing"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// mockUserRepo is a hand-written in-memory user repository for unit tests.
type mockUserRepo struct {
	users             map[string]*user.User
	updateUsernameErr error
	localeCalls       []string
	updateCalls       []struct {
		publicKey string
		username  string
	}
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*user.User)}
}

func (m *mockUserRepo) GetUserByPublicKey(publicKey string) (*user.User, error) {
	u, ok := m.users[publicKey]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) UpdateUsername(publicKey, username string) error {
	if m.updateUsernameErr != nil {
		return m.updateUsernameErr
	}
	m.updateCalls = append(m.updateCalls, struct {
		publicKey string
		username  string
	}{publicKey, username})
	u, ok := m.users[publicKey]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.Username = username
	return nil
}

func (m *mockUserRepo) UpdateLocale(publicKey, locale string) error {
	m.localeCalls = append(m.localeCalls, locale)
	u, ok := m.users[publicKey]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.Locale = locale
	return nil
}

// mockAppLister is a hand-written stub for the appLister dependency.
type mockAppLister struct {
	apps []*application.Application
	err  error
}

func (m *mockAppLister) GetApplicationsByMemberPublicKey(publicKey string) ([]*application.Application, error) {
	return m.apps, m.err
}

// mockEventService records produced events for assertions.
type mockEventService struct {
	produced []*event.Event
	err      error
}

func (m *mockEventService) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.produced = append(m.produced, e)
	return e, nil
}

func newTestRequestCtx(method, body string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetBody([]byte(body))
	return ctx
}

func setAuthUser(ctx *fasthttp.RequestCtx, u *user.User) {
	ctx.SetUserValue("user", u)
}

// Display-name shape validation (trim, empty, length, control chars,
// unicode-by-rune-count) is covered by TestNormalizeUsername_* in
// internal/user/password_test.go, now that profile.go delegates to
// user.NormalizeUsername instead of its own validateDisplayName.

// ---- UpdateProfile ----

func TestUpdateProfile_ShouldReturn401WhenNoUser(t *testing.T) {
	// given
	ep := NewProfileEndpoints(newMockUserRepo(), &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"Alice"}`)

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestUpdateProfile_ShouldReturn400WhenBodyInvalid(t *testing.T) {
	// given
	ep := NewProfileEndpoints(newMockUserRepo(), &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `not-json`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestUpdateProfile_ShouldReturn400WhenNameInvalid(t *testing.T) {
	// given
	ep := NewProfileEndpoints(newMockUserRepo(), &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"   "}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestUpdateProfile_ShouldReturn500WhenRepoUpdateFails(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.updateUsernameErr = fmt.Errorf("db error")
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"NewName"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}

// TestUpdateProfile_ShouldReturn409WhenUsernameTakenForPasswordLogin covers
// #126's rename collision: renaming into a username another,
// password-enabled account already holds surfaces as 409, not the generic
// 500 TestUpdateProfile_ShouldReturn500WhenRepoUpdateFails above covers.
func TestUpdateProfile_ShouldReturn409WhenUsernameTakenForPasswordLogin(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.updateUsernameErr = user.ErrUsernameTaken
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"TakenName"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

// TestUpdateProfile_ShouldPersistTrimmedNameAndReturnUpdatedUser also
// exercises the case where the caller has no password login at all - the
// mock repo's UpdateUsername succeeds unconditionally, mirroring an account
// for which the partial unique index never applies.
func TestUpdateProfile_ShouldPersistTrimmedNameAndReturnUpdatedUser(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"  NewName  "}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "NewName", repo.users["pk-1"].Username)
	assert.Contains(t, string(ctx.Response.Body()), `"username":"NewName"`)
}

func TestUpdateProfile_ShouldFanOutOneEventPerApplicationWithSpaceID(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	spaceID1 := "space-1"
	apps := &mockAppLister{apps: []*application.Application{
		{ID: "app-1", SpaceID: &spaceID1},
		{ID: "app-2"},
	}}
	events := &mockEventService{}
	ep := NewProfileEndpoints(repo, apps, events)
	ctx := newTestRequestCtx("PATCH", `{"displayName":"NewName"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Len(t, events.produced, 2)

	assert.Equal(t, event.EventTypeUserSettingsChanged, events.produced[0].Type)
	assert.Equal(t, "app-1", events.produced[0].ApplicationID)
	assert.Equal(t, "space-1", events.produced[0].SpaceID)
	assert.Equal(t, "app-1", events.produced[0].Data["applicationId"])
	assert.Equal(t, "NewName", events.produced[0].Data["displayName"])

	assert.Equal(t, "app-2", events.produced[1].ApplicationID)
	assert.Empty(t, events.produced[1].SpaceID)
}

func TestUpdateProfile_ShouldEchoCurrentAvatarStorageIdInFanOut(t *testing.T) {
	// given
	repo := newMockUserRepo()
	avatarID := "avatar-storage-id-1"
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName", AvatarStorageID: &avatarID}
	apps := &mockAppLister{apps: []*application.Application{{ID: "app-1"}}}
	events := &mockEventService{}
	ep := NewProfileEndpoints(repo, apps, events)
	ctx := newTestRequestCtx("PATCH", `{"displayName":"NewName"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName", AvatarStorageID: &avatarID})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Len(t, events.produced, 1)
	assert.Equal(t, avatarID, events.produced[0].Data["avatarStorageId"])
}

func TestUpdateProfile_ShouldNotWriteOrFanOutWhenNameUnchanged(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "SameName"}
	apps := &mockAppLister{apps: []*application.Application{{ID: "app-1"}}}
	events := &mockEventService{}
	ep := NewProfileEndpoints(repo, apps, events)
	ctx := newTestRequestCtx("PATCH", `{"displayName":"  SameName  "}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "SameName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.updateCalls)
	assert.Empty(t, events.produced)
}

func TestUpdateProfile_ShouldReturn200WhenFanOutFails(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	apps := &mockAppLister{apps: []*application.Application{{ID: "app-1"}}}
	events := &mockEventService{err: fmt.Errorf("broadcast failed")}
	ep := NewProfileEndpoints(repo, apps, events)
	ctx := newTestRequestCtx("PATCH", `{"displayName":"NewName"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "NewName", repo.users["pk-1"].Username)
}

func patchLocale(t *testing.T, body string, current *user.User) (*fasthttp.RequestCtx, *mockUserRepo, *mockEventService) {
	t.Helper()
	repo := newMockUserRepo()
	stored := *current
	repo.users[current.PublicKey] = &stored
	events := &mockEventService{}
	ep := NewProfileEndpoints(repo, &mockAppLister{apps: []*application.Application{{ID: "app-1"}}}, events)
	ctx := newTestRequestCtx("PATCH", body)
	setAuthUser(ctx, current)
	ep.UpdateProfile(ctx)
	return ctx, repo, events
}

func TestUpdateProfile_ShouldUpdateLocaleOnlyWithoutFanOut(t *testing.T) {
	// when
	ctx, repo, events := patchLocale(t, `{"locale":"pl"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []string{"pl"}, repo.localeCalls)
	assert.Empty(t, repo.updateCalls)
	assert.Empty(t, events.produced)
	assert.Contains(t, string(ctx.Response.Body()), `"locale":"pl"`)
}

func TestUpdateProfile_ShouldNormalizeLocaleToBaseLanguage(t *testing.T) {
	for raw, want := range map[string]string{"pl-PL": "pl", "PL": "pl", "pt_BR": "pt"} {
		// when
		ctx, repo, _ := patchLocale(t, `{"locale":"`+raw+`"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

		// then
		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), raw)
		assert.Equal(t, []string{want}, repo.localeCalls, raw)
	}
}

func TestUpdateProfile_ShouldReturn400WhenLocaleInvalid(t *testing.T) {
	for _, raw := range []string{"", "polish", "p1", "ü"} {
		// when
		ctx, repo, _ := patchLocale(t, `{"locale":"`+raw+`"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), raw)
		assert.Empty(t, repo.localeCalls, raw)
	}
}

func TestUpdateProfile_ShouldReturn400WhenBothFieldsAbsent(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.updateCalls)
	assert.Empty(t, repo.localeCalls)
}

func TestUpdateProfile_ShouldUpdateNameAndLocaleTogether(t *testing.T) {
	// when
	ctx, repo, events := patchLocale(t, `{"displayName":"Bob","locale":"de-AT"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "Bob", repo.users["pk-1"].Username)
	assert.Equal(t, []string{"de"}, repo.localeCalls)
	assert.Len(t, events.produced, 1)
	assert.Contains(t, string(ctx.Response.Body()), `"locale":"de"`)
}

func TestUpdateProfile_ShouldNotWriteLocaleWhenNameInvalid(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"displayName":"   ","locale":"pl"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.localeCalls)
}

func TestUpdateProfile_ShouldNotWriteWhenLocaleUnchanged(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"locale":"pl-PL"}`, &user.User{PublicKey: "pk-1", Username: "Alice", Locale: "pl"})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.localeCalls)
}
