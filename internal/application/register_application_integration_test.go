//go:build integration

package application

import (
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

func newRegisterPayload(appID, name, ownerKey string) *Application {
	return &Application{
		ID:   appID,
		Name: name,
		Members: []Member{
			{ID: appID + "-owner", Role: MemberRoleOwner, PublicKey: ownerKey},
		},
		ComponentGroups: []ComponentGroup{
			{ID: appID + "-group", Name: "Group", Components: []Component{{ID: appID + "-comp", Name: "Comp"}}},
		},
	}
}

func TestRepository_RegisterApplication_ShouldRollBackEverythingOnFailure_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)
	appID := uuid.NewString()
	keyA, keyB := "reg-rollback-a-"+appID, "reg-rollback-b-"+appID
	testdb.InsertTestUser(t, db, keyA)
	testdb.InsertTestUser(t, db, keyB)
	app := newRegisterPayload(appID, "Rollback", keyA)
	app.Members = append(app.Members, Member{ID: app.Members[0].ID, Role: MemberRoleMember, PublicKey: keyB})

	// when
	err := repo.RegisterApplication(app)

	// then
	assert.Error(t, err)
	live, err := repo.IsApplicationLive(appID)
	assert.NoError(t, err)
	assert.False(t, live)
	var rows int
	assert.NoError(t, db.QueryRow(`SELECT (SELECT COUNT(*) FROM members WHERE application_id = $1) + (SELECT COUNT(*) FROM component_groups WHERE application_id = $1)`, appID).Scan(&rows))
	assert.Equal(t, 0, rows)
}

func TestApplicationService_RegisterApplication_ShouldRejectOwnerOtherThanCaller_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	service := NewApplicationService(NewRepository(db), 0, "space-key")
	appID := uuid.NewString()
	caller := &user.User{PublicKey: "reg-caller-" + appID, Role: user.RoleUser}
	owner := "reg-owner-" + appID
	testdb.InsertTestUser(t, db, caller.PublicKey)
	testdb.InsertTestUser(t, db, owner)

	// when
	_, err := service.RegisterApplication(caller, newRegisterPayload(appID, "Spoofed", owner))

	// then
	assert.ErrorIs(t, err, ErrOwnerNotCaller)
	live, err := NewRepository(db).IsApplicationLive(appID)
	assert.NoError(t, err)
	assert.False(t, live)
}

func TestApplicationService_RegisterApplication_ShouldAllowSameCallerReRegister_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	service := NewApplicationService(NewRepository(db), 0, "space-key")
	appID := uuid.NewString()
	caller := &user.User{PublicKey: "reg-retry-" + appID, Role: user.RoleUser}
	testdb.InsertTestUser(t, db, caller.PublicKey)
	_, err := service.RegisterApplication(caller, newRegisterPayload(appID, "Retry", caller.PublicKey))
	assert.NoError(t, err)

	// when
	got, err := service.RegisterApplication(caller, newRegisterPayload(appID, "Retry", caller.PublicKey))

	// then
	assert.NoError(t, err)
	assert.Equal(t, appID, got.ID)
	assert.Len(t, got.Members, 1)
}

func TestApplicationService_RegisterApplication_ShouldRejectReRegisterByOtherCaller_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)
	service := NewApplicationService(repo, 0, "space-key")
	appID := uuid.NewString()
	first := &user.User{PublicKey: "reg-first-" + appID, Role: user.RoleUser}
	second := &user.User{PublicKey: "reg-second-" + appID, Role: user.RoleUser}
	testdb.InsertTestUser(t, db, first.PublicKey)
	testdb.InsertTestUser(t, db, second.PublicKey)
	_, err := service.RegisterApplication(first, newRegisterPayload(appID, "Original", first.PublicKey))
	assert.NoError(t, err)

	// when
	_, err = service.RegisterApplication(second, newRegisterPayload(appID, "Hijacked", second.PublicKey))

	// then
	assert.ErrorIs(t, err, ErrNotApplicationOwner)
	got, err := repo.GetApplicationByID(appID)
	assert.NoError(t, err)
	assert.Equal(t, "Original", got.Name)
}
