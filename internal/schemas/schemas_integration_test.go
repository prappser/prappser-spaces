//go:build integration

package schemas

import (
	"database/sql"
	"testing"

	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t, "schemas")
	t.Cleanup(func() { db.Close() })
	_, err := db.Exec(`DELETE FROM schema_bundle`)
	require.NoError(t, err)
	return db
}

func TestRepository_Get_NoRow_ShouldReturnNil(t *testing.T) {
	// given
	repo := NewRepository(newSchemaDB(t))

	// when
	got, err := repo.Get()

	// then
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestRepository_ShouldRoundTripContainerByteForByte(t *testing.T) {
	// given
	repo := NewRepository(newSchemaDB(t))
	raw := []byte("{\"k\":\"café\"}\x00\xff\n")

	// when
	require.NoError(t, repo.Save(3, raw))
	got, err := repo.Get()

	// then
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, 3, got.Bundle)
	assert.Equal(t, raw, got.Container)
}

func TestRepository_Save_ShouldUpsertSingleRow(t *testing.T) {
	// given
	db := newSchemaDB(t)
	repo := NewRepository(db)

	// when
	require.NoError(t, repo.Save(1, []byte("one")))
	require.NoError(t, repo.Save(2, []byte("two")))

	// then
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM schema_bundle`).Scan(&n))
	assert.Equal(t, 1, n)
	got, err := repo.Get()
	require.NoError(t, err)
	assert.Equal(t, 2, got.Bundle)
}

func TestRepository_Save_ShouldNeverLowerBundle(t *testing.T) {
	// given
	repo := NewRepository(newSchemaDB(t))

	// when / then
	require.NoError(t, repo.Save(5, []byte("five")))
	require.NoError(t, repo.Save(3, []byte("three")))
	got, err := repo.Get()
	require.NoError(t, err)
	assert.Equal(t, 5, got.Bundle)
	assert.Equal(t, []byte("five"), got.Container)

	require.NoError(t, repo.Save(7, []byte("seven")))
	got, err = repo.Get()
	require.NoError(t, err)
	assert.Equal(t, 7, got.Bundle)
	assert.Equal(t, []byte("seven"), got.Container)
}

func TestLoad_TamperedStoredRow_ShouldBeIgnoredAndKept(t *testing.T) {
	// given
	db := newSchemaDB(t)
	repo := NewRepository(db)
	pub, _ := newKey(t)
	require.NoError(t, repo.Save(9, []byte(`{"manifest":"x","signature":"y","files":{}}`)))
	svc := NewService(repo, pub, "")

	// when
	svc.Load(nil)

	// then
	assert.Nil(t, svc.Current())
	got, err := repo.Get()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, 9, got.Bundle)
}
