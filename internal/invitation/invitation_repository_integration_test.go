//go:build integration

package invitation

import (
	"testing"

	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetByApplicationID_ShouldReturnExpiresAtWhenSet(t *testing.T) {
	// given
	db := testdb.Connect(t, "invitation")
	t.Cleanup(func() { db.Close() })
	testdb.InsertTestUser(t, db, "creator-pk")
	_, err := db.Exec(`INSERT INTO applications (id, name, created_at, updated_at) VALUES ('app-1', 'app-1', 1, 1)`)
	require.NoError(t, err)
	repo := NewInvitationRepository(db)
	exp := int64(1900000000)
	require.NoError(t, repo.Create(&Invitation{ID: "with-exp", ApplicationID: "app-1", CreatedByPublicKey: "creator-pk", Role: "member", CreatedAt: 2, ExpiresAt: &exp}))
	require.NoError(t, repo.Create(&Invitation{ID: "no-exp", ApplicationID: "app-1", CreatedByPublicKey: "creator-pk", Role: "member", CreatedAt: 1}))

	// when
	invites, err := repo.GetByApplicationID("app-1")

	// then
	require.NoError(t, err)
	require.Len(t, invites, 2)
	assert.Equal(t, "with-exp", invites[0].ID)
	require.NotNil(t, invites[0].ExpiresAt)
	assert.Equal(t, exp, *invites[0].ExpiresAt)
	assert.Nil(t, invites[1].ExpiresAt)

	byID, err := repo.GetByID("with-exp")
	require.NoError(t, err)
	require.NotNil(t, byID.ExpiresAt)
	assert.Equal(t, exp, *byID.ExpiresAt)
}
