package invitation

import (
	"database/sql"
	"fmt"
)

// InvitationRepository defines the interface for invitation data access
type InvitationRepository interface {
	Create(invite *Invitation) error
	GetByID(id string) (*Invitation, error)
	Delete(id string) error
	IncrementUseCount(id string) error
	RecordUse(inviteID, userPublicKey string, useID string) error
	GetByApplicationID(appID string) ([]*Invitation, error)
	HasBeenUsedBy(inviteID, userPublicKey string) (bool, error)
}

type invitationRepository struct {
	db *sql.DB
}

func NewInvitationRepository(db *sql.DB) *invitationRepository {
	return &invitationRepository{db: db}
}

func (r *invitationRepository) Create(invite *Invitation) error {
	query := `
		INSERT INTO invitations (
			id, application_id, created_by_public_key,
			role, max_uses, used_count, created_at, space_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.Exec(query,
		invite.ID,
		invite.ApplicationID,
		invite.CreatedByPublicKey,
		invite.Role,
		invite.MaxUses,
		invite.UsedCount,
		invite.CreatedAt,
		invite.SpaceID,
	)

	return err
}

func (r *invitationRepository) GetByID(id string) (*Invitation, error) {
	query := `
		SELECT id, application_id, created_by_public_key,
		       role, max_uses, used_count, created_at
		FROM invitations
		WHERE id = $1
	`

	invite := &Invitation{}
	err := r.db.QueryRow(query, id).Scan(
		&invite.ID,
		&invite.ApplicationID,
		&invite.CreatedByPublicKey,
		&invite.Role,
		&invite.MaxUses,
		&invite.UsedCount,
		&invite.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invitation not found")
	}
	if err != nil {
		return nil, err
	}

	return invite, nil
}

func (r *invitationRepository) Delete(id string) error {
	query := `DELETE FROM invitations WHERE id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("invitation not found")
	}

	return nil
}

func (r *invitationRepository) IncrementUseCount(id string) error {
	query := `
		UPDATE invitations
		SET used_count = used_count + 1
		WHERE id = $1
	`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("invitation not found")
	}

	return nil
}

func (r *invitationRepository) RecordUse(inviteID, userPublicKey string, useID string) error {
	query := `
		INSERT INTO invitation_uses (id, invitation_id, user_public_key, used_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.Exec(query, useID, inviteID, userPublicKey, 0)
	return err
}

func (r *invitationRepository) GetByApplicationID(appID string) ([]*Invitation, error) {
	query := `
		SELECT id, application_id, created_by_public_key,
		       role, max_uses, used_count, created_at
		FROM invitations
		WHERE application_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invitations []*Invitation
	for rows.Next() {
		invite := &Invitation{}
		err := rows.Scan(
			&invite.ID,
			&invite.ApplicationID,
			&invite.CreatedByPublicKey,
			&invite.Role,
			&invite.MaxUses,
			&invite.UsedCount,
			&invite.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		invitations = append(invitations, invite)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return invitations, nil
}

func (r *invitationRepository) HasBeenUsedBy(inviteID, userPublicKey string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM invitation_uses
		WHERE invitation_id = $1 AND user_public_key = $2
	`

	var count int
	err := r.db.QueryRow(query, inviteID, userPublicKey).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
