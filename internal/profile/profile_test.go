package profile

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

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
	notifyModeCalls   []string
	timezoneCalls     []string
	seenAtCalls       []int64
	paymentCalls      []string
	paymentErr        error
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

func (m *mockUserRepo) UpdateTimezone(publicKey, tz string) error {
	m.timezoneCalls = append(m.timezoneCalls, tz)
	u, ok := m.users[publicKey]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.Timezone = tz
	return nil
}

func (m *mockUserRepo) UpdateNotifyMode(publicKey, mode string) error {
	m.notifyModeCalls = append(m.notifyModeCalls, mode)
	u, ok := m.users[publicKey]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.NotifyMode = mode
	return nil
}

func (m *mockUserRepo) UpdateNotificationsSeenAt(publicKey string, at int64) error {
	m.seenAtCalls = append(m.seenAtCalls, at)
	u, ok := m.users[publicKey]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.NotificationsSeenAt = max(u.NotificationsSeenAt, at)
	return nil
}

func (m *mockUserRepo) UpdatePaymentMethods(publicKey string, raw []byte) error {
	m.paymentCalls = append(m.paymentCalls, string(raw))
	if m.paymentErr != nil {
		return m.paymentErr
	}
	if _, ok := m.users[publicKey]; !ok {
		return fmt.Errorf("user not found")
	}
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

func TestUpdateProfile_ShouldNotChangeNotifyModeWhenUsernameTaken(t *testing.T) {
	// given
	repo := newMockUserRepo()
	repo.updateUsernameErr = user.ErrUsernameTaken
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "OldName"}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", `{"displayName":"TakenName","notifyMode":"chat"}`)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "OldName"})

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Empty(t, repo.notifyModeCalls)
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
	assert.Empty(t, repo.notifyModeCalls)
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

func TestUpdateProfile_ShouldUpdateNotifyModeOnlyWithoutFanOut(t *testing.T) {
	// when
	ctx, repo, events := patchLocale(t, `{"notifyMode":"chat"}`, &user.User{PublicKey: "pk-1", Username: "Alice", NotifyMode: user.NotifyModeAll})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []string{"chat"}, repo.notifyModeCalls)
	assert.Empty(t, repo.localeCalls)
	assert.Empty(t, repo.updateCalls)
	assert.Empty(t, events.produced)
	assert.Contains(t, string(ctx.Response.Body()), `"notifyMode":"chat"`)
}

func TestUpdateProfile_ShouldReturn400WhenNotifyModeInvalid(t *testing.T) {
	for _, raw := range []string{`""`, `"Chat"`, `"ALL"`, `"none"`, `1`, `true`, `["chat"]`, `{}`} {
		// when
		ctx, repo, _ := patchLocale(t, `{"notifyMode":`+raw+`}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), raw)
		assert.Empty(t, repo.notifyModeCalls, raw)
	}
}

func TestUpdateProfile_ShouldReturn400WhenNotifyModeIsNullAlone(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"notifyMode":null}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.notifyModeCalls)
}

func TestUpdateProfile_ShouldNotWriteWhenNotifyModeInvalidAlongsideValidName(t *testing.T) {
	// when
	ctx, repo, events := patchLocale(t, `{"displayName":"Bob","notifyMode":"x"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.updateCalls)
	assert.Empty(t, repo.notifyModeCalls)
	assert.Empty(t, events.produced)
}

func TestUpdateProfile_ShouldLeaveNotifyModeUnchangedWhenKeyMissing(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"locale":"pl"}`, &user.User{PublicKey: "pk-1", Username: "Alice", NotifyMode: user.NotifyModeChat})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.notifyModeCalls)
	assert.Contains(t, string(ctx.Response.Body()), `"notifyMode":"chat"`)
}

func TestUpdateProfile_ShouldNotWriteWhenNotifyModeUnchanged(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"notifyMode":"chat"}`, &user.User{PublicKey: "pk-1", Username: "Alice", NotifyMode: user.NotifyModeChat})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.notifyModeCalls)
}

func TestUpdateProfile_ShouldAcceptDailyNotifyMode(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"notifyMode":"daily"}`, &user.User{PublicKey: "pk-1", Username: "Alice", NotifyMode: user.NotifyModeAll})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []string{"daily"}, repo.notifyModeCalls)
}

func TestUpdateProfile_ShouldSaveTimezone(t *testing.T) {
	for _, tz := range []string{"Europe/Warsaw", ""} {
		// when
		ctx, repo, events := patchLocale(t, `{"timezone":"`+tz+`"}`, &user.User{PublicKey: "pk-1", Username: "Alice", Timezone: "America/New_York"})

		// then
		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), tz)
		assert.Equal(t, []string{tz}, repo.timezoneCalls, tz)
		assert.Empty(t, events.produced, tz)
		assert.Contains(t, string(ctx.Response.Body()), `"timezone":"`+tz+`"`, tz)
	}
}

func TestUpdateProfile_ShouldReturn400WhenTimezoneInvalid(t *testing.T) {
	for _, tz := range []string{"Mars/Base", "Local", "../etc/passwd"} {
		// when
		ctx, repo, _ := patchLocale(t, `{"timezone":"`+tz+`"}`, &user.User{PublicKey: "pk-1", Username: "Alice"})

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), tz)
		assert.Empty(t, repo.timezoneCalls, tz)
	}
}

func TestUpdateProfile_ShouldNotWriteWhenTimezoneUnchanged(t *testing.T) {
	// when
	ctx, repo, _ := patchLocale(t, `{"timezone":"Europe/Warsaw"}`, &user.User{PublicKey: "pk-1", Username: "Alice", Timezone: "Europe/Warsaw"})

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.timezoneCalls)
}

// ---- notificationsSeenAt ----

func patchSeenAt(t *testing.T, body string) (*mockUserRepo, *fasthttp.RequestCtx) {
	t.Helper()
	repo := newMockUserRepo()
	repo.users["pk-1"] = &user.User{PublicKey: "pk-1", Username: "Alice", NotificationsSeenAt: 10}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := newTestRequestCtx("PATCH", body)
	setAuthUser(ctx, &user.User{PublicKey: "pk-1", Username: "Alice", NotificationsSeenAt: 10})
	ep.UpdateProfile(ctx)
	return repo, ctx
}

func TestUpdateProfile_ShouldReturn400WhenNotificationsSeenAtNegative(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"notificationsSeenAt":-1}`)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.seenAtCalls)
}

func TestUpdateProfile_ShouldReturn400WhenNotificationsSeenAtMoreThanFiveMinutesAhead(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"notificationsSeenAt":`+strconv.FormatInt(time.Now().Unix()+310, 10)+`}`)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.seenAtCalls)
}

func TestUpdateProfile_ShouldAcceptNotificationsSeenAtFiveMinutesAhead(t *testing.T) {
	// given
	at := time.Now().Unix() + 300

	// when
	_, ctx := patchSeenAt(t, `{"notificationsSeenAt":`+strconv.FormatInt(at, 10)+`}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

func TestUpdateProfile_ShouldReturn400WhenNotificationsSeenAtNotInteger(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"notificationsSeenAt":"yesterday"}`)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.seenAtCalls)
}

func TestUpdateProfile_ShouldUpdateNotificationsSeenAtWhenOnlyFieldSent(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"notificationsSeenAt":100}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []int64{100}, repo.seenAtCalls)
	assert.Contains(t, string(ctx.Response.Body()), `"notificationsSeenAt":100`)
}

func TestUpdateProfile_ShouldLeaveNotificationsSeenAtUntouchedWhenAbsent(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"displayName":"Bob"}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Empty(t, repo.seenAtCalls)
	assert.Contains(t, string(ctx.Response.Body()), `"notificationsSeenAt":10`)
}

func TestUpdateProfile_ShouldUpdateNotificationsSeenAtTogetherWithDisplayName(t *testing.T) {
	// given / when
	repo, ctx := patchSeenAt(t, `{"displayName":"Bob","notificationsSeenAt":100}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []int64{100}, repo.seenAtCalls)
	assert.Equal(t, "Bob", repo.users["pk-1"].Username)
}

// ---- paymentMethods ----

func patchPayments(t *testing.T, body string) (*fasthttp.RequestCtx, *mockUserRepo, *mockEventService) {
	t.Helper()
	return patchLocale(t, body, &user.User{PublicKey: "pk-1", Username: "Alice"})
}

func TestUpdateProfile_ShouldStoreAcceptedPaymentMethodsOpaque(t *testing.T) {
	opaque := `[{"id":"cash","type":"cash","value":"","label":""},{"id":"b1","type":"blik","value":"123 456 789","label":"Me","extra":{"x":1}}]`
	for _, raw := range []string{`[]`, opaque} {
		// when
		ctx, repo, _ := patchPayments(t, `{"paymentMethods":`+raw+`}`)

		// then
		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), raw)
		assert.Equal(t, []string{raw}, repo.paymentCalls, raw)
	}
}

func TestUpdateProfile_ShouldReturn400WhenPaymentMethodsMalformedShape(t *testing.T) {
	shapes := []string{
		`{}`, `"x"`, `1`, `true`, `{"id":"a"}`,
		`[1]`, `["a"]`, `[null]`, `[[]]`, `[{},true]`,
	}
	for _, raw := range shapes {
		// when
		ctx, repo, _ := patchPayments(t, `{"paymentMethods":`+raw+`}`)

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), raw)
		assert.Empty(t, repo.paymentCalls, raw)
	}
}

func TestUpdateProfile_ShouldAcceptTwentyPaymentMethodsAndRejectTwentyOne(t *testing.T) {
	// given
	list := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("{},", n), ",") + "]" }

	// when
	okCtx, okRepo, _ := patchPayments(t, `{"paymentMethods":`+list(20)+`}`)
	tooManyCtx, tooManyRepo, _ := patchPayments(t, `{"paymentMethods":`+list(21)+`}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, okCtx.Response.StatusCode())
	assert.Len(t, okRepo.paymentCalls, 1)
	assert.Equal(t, fasthttp.StatusBadRequest, tooManyCtx.Response.StatusCode())
	assert.Empty(t, tooManyRepo.paymentCalls)
}

func TestUpdateProfile_ShouldRejectPaymentMethodsOverEightKilobytes(t *testing.T) {
	// given
	overhead := len(`[{"v":""}]`)
	fits := `[{"v":"` + strings.Repeat("a", 8192-overhead) + `"}]`
	over := `[{"v":"` + strings.Repeat("a", 8192-overhead+1) + `"}]`

	// when
	okCtx, okRepo, _ := patchPayments(t, `{"paymentMethods":`+fits+`}`)
	paddedCtx, paddedRepo, _ := patchPayments(t, `{"paymentMethods":   `+fits+`   }`)
	overCtx, overRepo, _ := patchPayments(t, `{"paymentMethods":`+over+`}`)

	// then
	assert.Len(t, fits, 8192)
	assert.Equal(t, fasthttp.StatusOK, okCtx.Response.StatusCode())
	assert.Len(t, okRepo.paymentCalls, 1)
	assert.Equal(t, fasthttp.StatusOK, paddedCtx.Response.StatusCode())
	assert.Len(t, paddedRepo.paymentCalls, 1)
	assert.Equal(t, fasthttp.StatusBadRequest, overCtx.Response.StatusCode())
	assert.Empty(t, overRepo.paymentCalls)
}

func TestUpdateProfile_ShouldAcceptEscapedBackslashBeforeU0000(t *testing.T) {
	// when
	ctx, repo, _ := patchPayments(t, `{"paymentMethods":[{"v":"\\u0000"}]}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, []string{`[{"v":"\\u0000"}]`}, repo.paymentCalls)
}

func TestUpdateProfile_ShouldReturn500WhenPaymentMethodsWriteFailsGenerically(t *testing.T) {
	// given
	repo := &mockUserRepo{users: map[string]*user.User{"pk-1": {PublicKey: "pk-1", Username: "Alice"}}, paymentErr: fmt.Errorf("connection reset")}
	ep := NewProfileEndpoints(repo, &mockAppLister{}, &mockEventService{})
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody([]byte(`{"paymentMethods":[{"id":"cash"}]}`))
	ctx.SetUserValue("user", repo.users["pk-1"])

	// when
	ep.UpdateProfile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}

// goccy decodes `null` into *json.RawMessage as a nil pointer, so the field is treated as absent.
func TestUpdateProfile_ShouldNeverWriteNullPaymentMethods(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		status      int
		localeCalls []string
	}{
		{"null alone", `{"paymentMethods":null}`, fasthttp.StatusBadRequest, nil},
		{"null next to locale", `{"locale":"pl","paymentMethods":null}`, fasthttp.StatusOK, []string{"pl"}},
	}
	for _, c := range cases {
		// when
		ctx, repo, _ := patchPayments(t, c.body)

		// then
		assert.Equal(t, c.status, ctx.Response.StatusCode(), c.name)
		assert.Equal(t, c.localeCalls, repo.localeCalls, c.name)
		assert.Empty(t, repo.paymentCalls, c.name)
	}
}

func TestUpdateProfile_ShouldWritePaymentMethodsWithoutFanOutOrOtherWrites(t *testing.T) {
	// when
	ctx, repo, events := patchPayments(t, `{"paymentMethods":[{"id":"cash"}]}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Len(t, repo.paymentCalls, 1)
	assert.Empty(t, events.produced)
	assert.Empty(t, repo.updateCalls)
}
