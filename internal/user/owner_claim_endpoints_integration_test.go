//go:build integration

package user

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func resetOwnerClaimState(t *testing.T, db *sql.DB) {
	t.Helper()
	t.Cleanup(func() { db.Close() })
	clean := func() {
		_, err := db.Exec("DELETE FROM space_owner_claim")
		assert.NoError(t, err)
		_, err = db.Exec("DELETE FROM users WHERE role = 'owner'")
		assert.NoError(t, err)
	}
	clean()
	t.Cleanup(clean)
}

func TestOwnerClaim_ShouldClaimOnceWithinWindow_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	resetOwnerClaimState(t, db)
	repo := NewUserRepository(db)
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), time.Now(), nil)

	// when
	firstReq := validClaimRequest(t, "alice")
	first := newClaimRequestCtx(t, firstReq)
	oe.Claim(first)
	second := newClaimRequestCtx(t, validClaimRequest(t, "bob"))
	oe.Claim(second)

	// then
	assert.Equal(t, fasthttp.StatusCreated, first.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusConflict, second.Response.StatusCode())
	var rows int
	assert.NoError(t, db.QueryRow("SELECT COUNT(*) FROM space_owner_claim").Scan(&rows))
	assert.Equal(t, 1, rows)
	var ownerKey string
	assert.NoError(t, db.QueryRow("SELECT owner_public_key FROM space_owner_claim WHERE id='main'").Scan(&ownerKey))
	assert.Equal(t, firstReq.PublicKey, ownerKey)
}

func TestOwnerClaim_ShouldRejectWhenWindowIsClosed_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	resetOwnerClaimState(t, db)
	repo := NewUserRepository(db)
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), time.Now().Add(-31*time.Minute), nil)

	// when
	ctx := newClaimRequestCtx(t, validClaimRequest(t, "alice"))
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	claimed, err := repo.HasClaim()
	assert.NoError(t, err)
	assert.False(t, claimed)
}
