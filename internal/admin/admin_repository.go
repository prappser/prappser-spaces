package admin

import (
	"database/sql"
	"fmt"

	"github.com/prappser/prappser-spaces/internal/application"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ponytail: no pagination (friends beta), add LIMIT/OFFSET if a space grows past a few thousand accounts.
func (r *Repository) ListAccounts() ([]AccountOverview, error) {
	query := `SELECT u.public_key, u.username, u.role, u.created_at,
			         COALESCE(s.bytes, 0), COALESCE(s.files, 0), COALESCE(a.owned, 0), d.last_seen_at
			  FROM users u
			  -- same rows as the quota sum in storage.Repository.GetUsedBytesByUploader; keep in step
			  LEFT JOIN (SELECT uploader_public_key AS pk, SUM(size_bytes) AS bytes, COUNT(*) AS files
			             FROM storage GROUP BY 1) s ON s.pk = u.public_key
			  LEFT JOIN (SELECT m.public_key AS pk, COUNT(DISTINCT ap.id) AS owned
			             FROM members m JOIN applications ap ON ap.id = m.application_id
			             WHERE m.role = 'owner' AND ap.deleted_at IS NULL AND ` + application.ActiveMemberPredicate + `
			             GROUP BY 1) a ON a.pk = u.public_key
			  LEFT JOIN (SELECT user_public_key AS pk, MAX(last_seen_at) AS last_seen_at
			             FROM user_devices GROUP BY 1) d ON d.pk = u.public_key
			  ORDER BY u.created_at, u.public_key`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts: %w", err)
	}
	defer rows.Close()

	accounts := []AccountOverview{}
	for rows.Next() {
		var a AccountOverview
		if err := rows.Scan(&a.PublicKey, &a.Username, &a.Role, &a.CreatedAt, &a.StorageBytes, &a.FileCount, &a.OwnedApps, &a.LastActiveAt); err != nil {
			return nil, fmt.Errorf("failed to scan account: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate accounts: %w", err)
	}
	return accounts, nil
}
