//go:build integration

// Package testdb provides per-package Postgres schema isolation for
// integration tests.
package testdb

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/lib/pq"
)

// Connect opens a *sql.DB scoped to a schema private to pkg (e.g. "user",
// "push", "keys") and applies the real files/migrations against it. Schema
// isolation plus real migrations mean the test schema can't drift from
// production, and packages can run their integration tests in parallel
// instead of needing `-p 1`.
func Connect(t *testing.T, pkg string) *sql.DB {
	t.Helper()

	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		baseURL = "postgres://test:test@localhost:5433/prappser_test?sslmode=disable"
	}
	schemaName := "test_" + pkg

	testURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("Failed to parse TEST_DATABASE_URL: %v", err)
	}
	q := testURL.Query()
	q.Set("search_path", schemaName)
	testURL.RawQuery = q.Encode()

	// Throwaway connection for schema creation + migrations: postgres.WithInstance
	// pins a *sql.Conn for the lifetime of the migrate.Migrate it backs, and
	// that conn is only released by m.Close() - which also closes the *sql.DB
	// it was opened on. Running that against a dedicated migDB (rather than
	// the db returned to the caller) means m.Close() here can't take the
	// caller's connection down with it.
	migDB, err := sql.Open("postgres", testURL.String())
	if err != nil {
		t.Fatalf("Failed to open migration connection for schema %s: %v", schemaName, err)
	}
	defer migDB.Close()
	if _, err := migDB.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, pq.QuoteIdentifier(schemaName))); err != nil {
		t.Fatalf("Failed to create schema %s: %v", schemaName, err)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("Failed to resolve testdb.go's own path")
	}
	migrationsDir, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", "files", "migrations"))
	if err != nil {
		t.Fatalf("Failed to resolve migrations path: %v", err)
	}
	migrationsURL := "file://" + migrationsDir

	driver, err := postgres.WithInstance(migDB, &postgres.Config{})
	if err != nil {
		t.Fatalf("Failed to create migrate driver: %v", err)
	}
	m, err := migrate.NewWithDatabaseInstance(migrationsURL, "postgres", driver)
	if err != nil {
		t.Fatalf("Failed to create migrate instance: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("Failed to run migrations against schema %s: %v", schemaName, err)
	}
	// m.Close() tears down the pinned conn along with migDB (a throwaway),
	// not the db returned to the caller below.
	if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
		t.Fatalf("Failed to close migrate instance for schema %s: src=%v db=%v", schemaName, srcErr, dbErr)
	}

	db, err := sql.Open("postgres", testURL.String())
	if err != nil {
		t.Fatalf("Failed to open db for schema %s: %v", schemaName, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping db for schema %s: %v", schemaName, err)
	}

	rows, err := db.Query(
		`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations'`,
		schemaName,
	)
	if err != nil {
		t.Fatalf("Failed to list tables in schema %s: %v", schemaName, err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("Failed to iterate tables in schema %s: %v", schemaName, err)
	}

	if len(tables) > 0 {
		quoted := make([]string, len(tables))
		for i, tbl := range tables {
			quoted[i] = pq.QuoteIdentifier(tbl)
		}
		truncateSQL := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", strings.Join(quoted, ", "))
		if _, err := db.Exec(truncateSQL); err != nil {
			t.Fatalf("Failed to truncate tables in schema %s: %v", schemaName, err)
		}
	}

	return db
}

// InsertTestUser inserts a bare-minimum users row. The users schema is
// strict: issuer is NOT NULL with no default, and role is CHECK'd to
// owner/user/guest - self-pinning issuer to publicKey (as every real
// self-registered account does) satisfies both.
func InsertTestUser(t *testing.T, db *sql.DB, publicKey string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1)",
		publicKey, "test-user-"+publicKey, "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user %s: %v", publicKey, err)
	}
}
