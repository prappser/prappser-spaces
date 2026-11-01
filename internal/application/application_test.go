package application

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
)

func createTestUser() *user.User {
	return &user.User{
		PublicKey: "test-public-key",
		Username:  "testuser",
		Role:      "owner",
		CreatedAt: time.Now().Unix(),
	}
}

func createRegularUser() *user.User {
	return &user.User{
		PublicKey: "regular-public-key",
		Username:  "regularuser",
		Role:      user.RoleUser,
		CreatedAt: time.Now().Unix(),
	}
}

func createBasicApplication(testUser *user.User, appName, appID string) *Application {
	return &Application{
		ID:   appID,
		Name: appName,
		Members: []Member{
			{
				ID:        appID + "-member-1", // Make member ID unique per application
				Role:      MemberRoleOwner,
				PublicKey: testUser.PublicKey,
			},
		},
		ComponentGroups: []ComponentGroup{
			{
				ID:         appID + "-group-1", // Also make group ID unique
				Name:       "Default Group",
				Index:      0,
				Components: []Component{},
			},
		},
	}
}

func TestApplicationService_RegisterApplication_ShouldCreateApplicationWithComponents(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := &Application{
		ID:   "test-app-complex-id",
		Name: "Test App",
		Members: []Member{
			{
				ID:        "member-1",
				Role:      MemberRoleOwner,
				PublicKey: testUser.PublicKey,
			},
		},
		ComponentGroups: []ComponentGroup{
			{
				ID:    "group-1",
				Name:  "UI Components",
				Index: 0,
				Components: []Component{
					{
						ID:   "comp-1",
						Name: "Button",
						Data: map[string]interface{}{
							"type": "button",
							"text": "Click me",
						},
						Index: 0,
					},
					{
						ID:   "comp-2",
						Name: "Input",
						Data: map[string]interface{}{
							"type":        "input",
							"placeholder": "Enter text",
						},
						Index: 1,
					},
				},
			},
		},
	}

	// when
	resultApp, err := appService.RegisterApplication(testUser, app)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if resultApp.Name != "Test App" {
		t.Errorf("Expected app name 'Test App', got '%s'", resultApp.Name)
	}

	if len(resultApp.ComponentGroups) != 1 {
		t.Errorf("Expected 1 component group, got %d", len(resultApp.ComponentGroups))
	}

	if len(resultApp.ComponentGroups[0].Components) != 2 {
		t.Errorf("Expected 2 components, got %d", len(resultApp.ComponentGroups[0].Components))
	}

	if len(resultApp.Members) != 1 {
		t.Errorf("Expected 1 member, got %d", len(resultApp.Members))
	}

	if resultApp.Members[0].Role != MemberRoleOwner {
		t.Errorf("Expected member role to be owner, got %s", resultApp.Members[0].Role)
	}
}

func TestApplicationService_GetApplication_ShouldReturnCompleteApplicationData(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(testUser, "Test App", "test-app-get-id")
	app.ComponentGroups[0].Name = "Data Components"
	app.ComponentGroups[0].Components = []Component{
		{
			ID:   "comp-data-1",
			Name: "DataStore",
			Data: map[string]interface{}{
				"type": "store",
			},
			Index: 0,
		},
	}

	registeredApp, err := appService.RegisterApplication(testUser, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	retrievedApp, err := appService.GetApplication(registeredApp.ID, testUser)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if retrievedApp.ID != registeredApp.ID {
		t.Errorf("Expected app ID '%s', got '%s'", registeredApp.ID, retrievedApp.ID)
	}

	if retrievedApp.Name != "Test App" {
		t.Errorf("Expected app name 'Test App', got '%s'", retrievedApp.Name)
	}
}

func TestApplicationService_GetApplication_ShouldReturnErrorForUnauthorizedUser(t *testing.T) {
	// given
	owner := createTestUser()

	// Create another user
	otherUser := &user.User{
		PublicKey: "other-public-key",
		Username:  "otheruser",
		Role:      "owner",
		CreatedAt: time.Now().Unix(),
	}

	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(owner, "Owner App", "owner-app-id")

	registeredApp, err := appService.RegisterApplication(owner, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	_, err = appService.GetApplication(registeredApp.ID, otherUser)

	// then
	if err == nil {
		t.Fatal("Expected error for unauthorized user, got nil")
	}

	if err.Error() != "unauthorized: not a member of this application" {
		t.Errorf("Expected 'unauthorized: not a member of this application' error, got '%s'", err.Error())
	}
}

func TestApplicationService_ListApplications_ShouldReturnUserApplicationsOnly(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app1 := createBasicApplication(testUser, "App 1", "test-app-id-1")

	app2 := createBasicApplication(testUser, "App 2", "test-app-id-2")

	_, err := appService.RegisterApplication(testUser, app1)
	if err != nil {
		t.Fatalf("Failed to register first application: %v", err)
	}

	_, err = appService.RegisterApplication(testUser, app2)
	if err != nil {
		t.Fatalf("Failed to register second application: %v", err)
	}

	// when
	apps, err := appService.ListApplications(testUser)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(apps) != 2 {
		t.Errorf("Expected 2 applications, got %d", len(apps))
	}
}

func TestApplicationService_GetApplicationState_ShouldReturnStateWithCorrectTimestamp(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(testUser, "State Test App", "state-test-app-id")

	registeredApp, err := appService.RegisterApplication(testUser, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	state, err := appService.GetApplicationState(registeredApp.ID, testUser)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if state.ID != app.ID {
		t.Errorf("Expected state ID '%s', got '%s'", app.ID, state.ID)
	}

	if state.Name != "State Test App" {
		t.Errorf("Expected state name 'State Test App', got '%s'", state.Name)
	}

	if state.UpdatedAt != app.UpdatedAt {
		t.Errorf("Expected state updated_at %d, got %d", app.UpdatedAt, state.UpdatedAt)
	}
}

func TestApplicationService_RegisterApplication_ShouldReturnErrorForEmptyName(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(testUser, "", "empty-name-test-id")
	app.Name = "" // Explicitly set empty name to test validation

	// when
	_, err := appService.RegisterApplication(testUser, app)

	// then
	if err == nil {
		t.Fatal("Expected error for empty application name, got nil")
	}
}

func TestApplicationService_DeleteApplication_ShouldDeleteApplicationSuccessfully(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(testUser, "App to Delete", "delete-test-app-id")
	app.ComponentGroups[0].Components = []Component{
		{
			ID:   "comp-delete-1",
			Name: "Test Component",
			Data: map[string]interface{}{
				"test": "data",
			},
			Index: 0,
		},
	}

	registeredApp, err := appService.RegisterApplication(testUser, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	err = appService.DeleteApplication(registeredApp.ID, testUser)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify application is deleted
	_, err = appService.GetApplication(registeredApp.ID, testUser)
	if err == nil {
		t.Fatal("Expected error when getting deleted application, got nil")
	}
}

func TestApplicationService_DeleteApplication_ShouldReturnErrorForUnauthorizedUser(t *testing.T) {
	// given
	owner := createTestUser()
	otherUser := &user.User{
		PublicKey: "other-public-key",
		Username:  "otheruser",
		Role:      "owner",
		CreatedAt: time.Now().Unix(),
	}

	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := createBasicApplication(owner, "Owner's App", "owner-delete-app-id")

	registeredApp, err := appService.RegisterApplication(owner, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	err = appService.DeleteApplication(registeredApp.ID, otherUser)

	// then
	if err == nil {
		t.Fatal("Expected error for unauthorized user, got nil")
	}

	if err.Error() != "unauthorized" {
		t.Errorf("Expected 'unauthorized' error, got '%s'", err.Error())
	}
}

func TestApplicationService_DeleteApplication_ShouldRejectAdmin(t *testing.T) {
	// given
	owner := createTestUser()
	admin := &user.User{
		PublicKey: "admin-public-key",
		Username:  "adminuser",
		Role:      user.RoleUser,
		CreatedAt: time.Now().Unix(),
	}
	app := createBasicApplication(owner, "Owner's App", "admin-delete-app-id")
	app.Members = append(app.Members, Member{ID: "admin-delete-app-id-member-2", Role: MemberRoleAdmin, PublicKey: admin.PublicKey})
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")
	registeredApp, err := appService.RegisterApplication(owner, app)
	if err != nil {
		t.Fatalf("Failed to register application: %v", err)
	}

	// when
	err = appService.DeleteApplication(registeredApp.ID, admin)

	// then
	if err == nil {
		t.Fatal("Expected error for admin deleting the application, got nil")
	}
	if err.Error() != "unauthorized" {
		t.Errorf("Expected 'unauthorized' error, got '%s'", err.Error())
	}
	if _, err := appService.GetApplication(registeredApp.ID, owner); err != nil {
		t.Errorf("Expected application to still exist, got: %v", err)
	}
}

func TestApplicationService_DeleteApplication_ShouldReturnErrorForNonExistentApp(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	// when
	err := appService.DeleteApplication("non-existent-id", testUser)

	// then
	if err == nil {
		t.Fatal("Expected error for non-existent application, got nil")
	}

	if err.Error() != "application not found" {
		t.Errorf("Expected 'application not found' error, got '%s'", err.Error())
	}
}

func TestApplicationService_RegisterApplication_ShouldRoundTripMember(t *testing.T) {
	// given
	testUser := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	app := &Application{
		ID:   "member-roundtrip-test-id",
		Name: "Member Roundtrip App",
		Members: []Member{
			{
				ID:        "member-roundtrip-1",
				Role:      MemberRoleOwner,
				PublicKey: testUser.PublicKey,
			},
		},
		ComponentGroups: []ComponentGroup{
			{
				ID:         "member-roundtrip-group-1",
				Name:       "Default Group",
				Index:      0,
				Components: []Component{},
			},
		},
	}

	// when
	registeredApp, err := appService.RegisterApplication(testUser, app)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	retrievedApp, err := appService.GetApplication(registeredApp.ID, testUser)
	if err != nil {
		t.Fatalf("Expected no error retrieving app, got: %v", err)
	}

	if len(retrievedApp.Members) != 1 {
		t.Fatalf("Expected 1 member, got %d", len(retrievedApp.Members))
	}

	if retrievedApp.Members[0].PublicKey != testUser.PublicKey {
		t.Errorf("Expected member PublicKey %q, got %q", testUser.PublicKey, retrievedApp.Members[0].PublicKey)
	}

	if retrievedApp.Members[0].Role != MemberRoleOwner {
		t.Errorf("Expected member Role %q, got %q", MemberRoleOwner, retrievedApp.Members[0].Role)
	}
}

// seedExpiryTestMembers creates one application with three members exercising
// every MembershipExpiresAt state #117 cares about: already expired, expires
// in the future, and never expires (nil) - used by the membership-expiry
// filtering tests below.
func seedExpiryTestMembers(t *testing.T, appRepo *MemoryRepository, appID string) {
	t.Helper()
	if err := appRepo.RegisterApplication(&Application{ID: appID, Name: "Expiry Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}

	past := time.Now().Add(-1 * time.Hour).Unix()
	future := time.Now().Add(1 * time.Hour).Unix()

	members := []*Member{
		{ID: "member-expired", ApplicationID: appID, Role: MemberRoleMember, PublicKey: "expired-pk", MembershipExpiresAt: &past},
		{ID: "member-future", ApplicationID: appID, Role: MemberRoleMember, PublicKey: "future-pk", MembershipExpiresAt: &future},
		{ID: "member-forever", ApplicationID: appID, Role: MemberRoleMember, PublicKey: "forever-pk"},
	}
	for _, m := range members {
		if err := appRepo.CreateMember(m); err != nil {
			t.Fatalf("Failed to create member %s: %v", m.PublicKey, err)
		}
	}
}

func TestMemoryRepository_GetMembersByApplicationID_ShouldExcludeExpiredMembers(t *testing.T) {
	// given
	appRepo := NewMemoryRepository()
	appID := "expiry-test-app-1"
	seedExpiryTestMembers(t, appRepo, appID)

	// when
	members, err := appRepo.GetMembersByApplicationID(appID)

	// then: the expired member is filtered out, the future and never-expiring ones stay
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("Expected 2 active members, got %d", len(members))
	}
	for _, m := range members {
		if m.PublicKey == "expired-pk" {
			t.Errorf("Expected expired member to be excluded, but it was returned")
		}
	}
}

func TestMemoryRepository_IsMember_ShouldTreatExpiredMembershipAsNotAMember(t *testing.T) {
	// given
	appRepo := NewMemoryRepository()
	appID := "expiry-test-app-2"
	seedExpiryTestMembers(t, appRepo, appID)

	// when / then
	isMember, err := appRepo.IsMember(appID, "expired-pk")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if isMember {
		t.Error("Expected expired member to not be a member")
	}

	isMember, err = appRepo.IsMember(appID, "future-pk")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !isMember {
		t.Error("Expected future-expiring member to still be a member")
	}

	isMember, err = appRepo.IsMember(appID, "forever-pk")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if !isMember {
		t.Error("Expected member with no expiry to still be a member")
	}
}

func TestMemoryRepository_GetMemberCount_ShouldExcludeExpiredMembers(t *testing.T) {
	// given
	appRepo := NewMemoryRepository()
	appID := "expiry-test-app-3"
	seedExpiryTestMembers(t, appRepo, appID)

	// when
	count, err := appRepo.GetMemberCount(appID)

	// then: only the future and never-expiring members count
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected member count 2, got %d", count)
	}
}

func registerN(t *testing.T, s *ApplicationService, u *user.User, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("limit-app-%d", i)
		if _, err := s.RegisterApplication(u, createBasicApplication(u, id, id)); err != nil {
			t.Fatalf("setup register %s: %v", id, err)
		}
	}
}

func TestApplicationService_RegisterApplication_AtLimit_ShouldReturnErrAppLimitReached(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 2, "space-key")
	registerN(t, appService, testUser, 2)

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "over", "over"))

	// then
	if !errors.Is(err, ErrAppLimitReached) {
		t.Fatalf("Expected ErrAppLimitReached, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_UnderLimit_ShouldSucceed(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 2, "space-key")
	registerN(t, appService, testUser, 1)

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "second", "second"))

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_SpaceOwnerExempt_ShouldSucceedAtLimit(t *testing.T) {
	// given
	testUser := createTestUser()
	appService := NewApplicationService(NewMemoryRepository(), 1, "space-key")
	registerN(t, appService, testUser, 1)

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "extra", "extra"))

	// then
	if err != nil {
		t.Fatalf("Expected no error for exempt caller, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_ZeroLimit_ShouldBeUnlimited(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")

	// when
	registerN(t, appService, testUser, 5)

	// then: registerN fails the test on any error
}

func TestApplicationService_RegisterApplication_ReRegisterLiveAppAtLimit_ShouldSucceed(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 1, "space-key")
	registerN(t, appService, testUser, 1)

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "renamed", "limit-app-0"))

	// then
	if err != nil {
		t.Fatalf("Expected re-register of live app to succeed, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_SoftDeletedApp_ShouldNotCountTowardsLimit(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 1, "space-key")
	registerN(t, appService, testUser, 1)
	if err := appService.DeleteApplication("limit-app-0", testUser); err != nil {
		t.Fatalf("setup delete: %v", err)
	}

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "fresh", "fresh"))

	// then
	if err != nil {
		t.Fatalf("Expected deleted app not to count, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_ReviveSoftDeletedAppAtLimit_ShouldReturnErrAppLimitReached(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 1, "space-key")
	registerN(t, appService, testUser, 1)
	if err := appService.DeleteApplication("limit-app-0", testUser); err != nil {
		t.Fatalf("setup delete: %v", err)
	}
	if _, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "other", "other")); err != nil {
		t.Fatalf("setup register: %v", err)
	}

	// when
	_, err := appService.RegisterApplication(testUser, createBasicApplication(testUser, "revived", "limit-app-0"))

	// then
	if !errors.Is(err, ErrAppLimitReached) {
		t.Fatalf("Expected ErrAppLimitReached when reviving at limit, got: %v", err)
	}
}

func TestApplicationService_RegisterApplication_ShouldRejectOwnerOtherThanCaller(t *testing.T) {
	// given
	caller := createRegularUser()
	other := createTestUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")

	// when
	_, err := appService.RegisterApplication(caller, createBasicApplication(other, "Spoofed", "spoofed-app"))

	// then
	assert.ErrorIs(t, err, ErrOwnerNotCaller)
	live, _ := appRepo.IsApplicationLive("spoofed-app")
	assert.False(t, live)
}

func TestApplicationService_RegisterApplication_ShouldRejectReRegisterOfAppOwnedByOther(t *testing.T) {
	// given
	owner := createTestUser()
	attacker := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")
	_, err := appService.RegisterApplication(owner, createBasicApplication(owner, "Original", "contested-app"))
	assert.NoError(t, err)

	// when
	_, err = appService.RegisterApplication(attacker, createBasicApplication(attacker, "Hijacked", "contested-app"))

	// then
	assert.ErrorIs(t, err, ErrNotApplicationOwner)
	got, err := appService.GetApplication("contested-app", owner)
	assert.NoError(t, err)
	assert.Equal(t, "Original", got.Name)
}

func TestApplicationService_RegisterApplication_ShouldAllowSameOwnerReRegister(t *testing.T) {
	// given
	owner := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")
	_, err := appService.RegisterApplication(owner, createBasicApplication(owner, "First", "retry-app"))
	assert.NoError(t, err)

	// when
	got, err := appService.RegisterApplication(owner, createBasicApplication(owner, "Second", "retry-app"))

	// then
	assert.NoError(t, err)
	assert.Equal(t, "Second", got.Name)
}

func TestApplicationService_RegisterApplication_ShouldSetSpaceKeyAndSpaceIDFromServiceAndCaller(t *testing.T) {
	// given
	caller := createRegularUser()
	caller.SpaceID = "caller-space"
	appService := NewApplicationService(NewMemoryRepository(), 0, "service-space-key")
	app := createBasicApplication(caller, "Spaced", "spaced-app")
	clientKey, clientSpace := "client-key", "client-space"
	app.SpacePublicKey = &clientKey
	app.SpaceID = &clientSpace

	// when
	got, err := appService.RegisterApplication(caller, app)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "service-space-key", *got.SpacePublicKey)
	assert.Equal(t, "caller-space", *got.SpaceID)
}

func TestApplicationService_RegisterApplication_ShouldRejectEmptyMemberIDBeforeWriting(t *testing.T) {
	// given
	caller := createRegularUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")
	app := createBasicApplication(caller, "Bad", "bad-member-app")
	app.Members = append(app.Members, Member{ID: "", Role: MemberRoleMember, PublicKey: "someone"})

	// when
	_, err := appService.RegisterApplication(caller, app)

	// then
	assert.Error(t, err)
	live, _ := appRepo.IsApplicationLive("bad-member-app")
	assert.False(t, live)
}

func TestApplicationService_RegisterApplication_NilCaller_ShouldReturnError(t *testing.T) {
	// given
	testUser := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")

	// when
	_, err := appService.RegisterApplication(nil, createBasicApplication(testUser, "app", "app"))

	// then
	assert.Error(t, err)
}

func TestApplicationService_RegisterApplication_ShouldKeepClientSpaceIDWhenCallerHasNone(t *testing.T) {
	// given
	testUser := createTestUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")
	clientSpaceID := "client-space-id"
	app := createBasicApplication(testUser, "App", "keep-space-id-app")
	app.SpaceID = &clientSpaceID

	// when
	registered, err := appService.RegisterApplication(testUser, app)

	// then
	assert.NoError(t, err)
	if assert.NotNil(t, registered.SpaceID) {
		assert.Equal(t, "client-space-id", *registered.SpaceID)
	}
}

func agentOf(u *user.User) *user.User {
	return &user.User{PublicKey: u.PublicKey, Role: u.Role, Agent: true}
}

func TestApplication_AgentAllowed_ShouldAllowHumanWhenFlagOff(t *testing.T) {
	// given
	app := &Application{AgentReadEnabled: false, Members: []Member{{Role: MemberRoleOwner, PublicKey: "owner"}}}

	// when
	allowed := app.AgentAllowed(&user.User{PublicKey: "admin"})

	// then
	assert.True(t, allowed)
}

func TestApplication_AgentAllowed_ShouldAllowAgentWhenFlagOn(t *testing.T) {
	// given
	app := &Application{AgentReadEnabled: true, Members: []Member{{Role: MemberRoleOwner, PublicKey: "owner"}}}

	// when
	allowed := app.AgentAllowed(&user.User{PublicKey: "admin", Agent: true})

	// then
	assert.True(t, allowed)
}

func TestApplication_AgentAllowed_ShouldDenyNonOwnerAgentWhenFlagOff(t *testing.T) {
	// given
	app := &Application{AgentReadEnabled: false, Members: []Member{
		{Role: MemberRoleOwner, PublicKey: "owner"},
		{Role: MemberRoleAdmin, PublicKey: "admin"},
	}}

	// when
	allowed := app.AgentAllowed(&user.User{PublicKey: "admin", Agent: true})

	// then
	assert.False(t, allowed)
}

func TestApplication_AgentAllowed_ShouldAllowOwnerAgentWhenFlagOff(t *testing.T) {
	// given
	app := &Application{AgentReadEnabled: false, Members: []Member{{Role: MemberRoleOwner, PublicKey: "owner"}}}

	// when
	allowed := app.AgentAllowed(&user.User{PublicKey: "owner", Agent: true})

	// then
	assert.True(t, allowed)
}

func TestApplicationService_ListApplications_ShouldHideAgentOffAppsFromNonOwnerAgent(t *testing.T) {
	// given
	owner := createTestUser()
	member := createRegularUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")
	for _, id := range []string{"open-app", "closed-app"} {
		app := createBasicApplication(owner, id, id)
		app.Members = append(app.Members, Member{ID: id + "-m2", Role: MemberRoleMember, PublicKey: member.PublicKey})
		_, err := appService.RegisterApplication(owner, app)
		assert.NoError(t, err)
	}
	assert.NoError(t, appRepo.SetAgentReadEnabled("closed-app", false))

	// when
	memberAgentApps, err1 := appService.ListApplications(agentOf(member))
	ownerAgentApps, err2 := appService.ListApplications(agentOf(owner))
	memberApps, err3 := appService.ListApplications(member)

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)
	assert.Len(t, memberAgentApps, 1)
	assert.Equal(t, "open-app", memberAgentApps[0].ID)
	assert.Len(t, ownerAgentApps, 2)
	assert.Len(t, memberApps, 2)
}

func TestApplicationService_GetApplication_ShouldReturnErrAgentReadOffForNonOwnerAgent(t *testing.T) {
	// given
	owner := createTestUser()
	member := createRegularUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")
	app := createBasicApplication(owner, "App", "app-1")
	app.Members = append(app.Members, Member{ID: "m2", Role: MemberRoleMember, PublicKey: member.PublicKey})
	_, err := appService.RegisterApplication(owner, app)
	assert.NoError(t, err)
	assert.NoError(t, appRepo.SetAgentReadEnabled("app-1", false))

	// when
	_, agentErr := appService.GetApplication("app-1", agentOf(member))
	_, humanErr := appService.GetApplication("app-1", member)

	// then
	assert.ErrorIs(t, agentErr, ErrAgentReadOff)
	assert.NoError(t, humanErr)
}

func TestApplicationService_SetAgentRead_ShouldAllowOwnerAndRejectOthers(t *testing.T) {
	// given
	owner := createTestUser()
	member := createRegularUser()
	appRepo := NewMemoryRepository()
	appService := NewApplicationService(appRepo, 0, "space-key")
	app := createBasicApplication(owner, "App", "app-1")
	app.Members = append(app.Members, Member{ID: "m2", Role: MemberRoleAdmin, PublicKey: member.PublicKey})
	_, err := appService.RegisterApplication(owner, app)
	assert.NoError(t, err)

	// when
	memberErr := appService.SetAgentRead("app-1", member, false)
	ownerErr := appService.SetAgentRead("app-1", owner, false)

	// then
	assert.ErrorIs(t, memberErr, ErrNotApplicationOwner)
	assert.NoError(t, ownerErr)
	got, err := appRepo.GetApplicationByID("app-1")
	assert.NoError(t, err)
	assert.False(t, got.AgentReadEnabled)
}

func TestApplicationService_SetAgentRead_ShouldReturnNotFoundForUnknownApp(t *testing.T) {
	// given
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")

	// when
	err := appService.SetAgentRead("missing", createTestUser(), false)

	// then
	assert.ErrorIs(t, err, ErrNotFound)
}
