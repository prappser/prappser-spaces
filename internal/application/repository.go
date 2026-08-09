package application

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// activeMemberPredicate is the whole of #117's enforcement: membership is
// evaluated lazily at read time, never by a scheduler.
const activeMemberPredicate = `(m.membership_expires_at IS NULL OR m.membership_expires_at > EXTRACT(EPOCH FROM NOW()))`

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateApplication(app *Application) error {
	query := `INSERT INTO applications (id, name, icon, space_public_key, space_id, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6, $7)
			  ON CONFLICT (id) DO UPDATE SET
			    name = EXCLUDED.name,
			    icon = EXCLUDED.icon,
			    space_id = EXCLUDED.space_id,
			    updated_at = EXCLUDED.updated_at,
			    deleted_at = NULL`

	_, err := r.db.Exec(query, app.ID, app.Name, app.Icon, app.SpacePublicKey, app.SpaceID, app.CreatedAt, app.UpdatedAt)
	return err
}

func (r *Repository) GetApplicationByID(id string) (*Application, error) {
	query := `SELECT id, name, icon, space_public_key, space_id, created_at, updated_at, last_sequence
			  FROM applications WHERE id = $1 AND deleted_at IS NULL`

	app := &Application{}
	var lastSequence sql.NullInt64
	var spaceID sql.NullString
	err := r.db.QueryRow(query, id).Scan(
		&app.ID, &app.Name, &app.Icon, &app.SpacePublicKey, &spaceID, &app.CreatedAt, &app.UpdatedAt,
		&lastSequence,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("application not found")
	}
	if err != nil {
		return nil, err
	}

	if lastSequence.Valid {
		app.LastSequence = &lastSequence.Int64
	}
	if spaceID.Valid {
		app.SpaceID = &spaceID.String
	}

	// Load component groups
	groups, err := r.GetComponentGroupsByApplicationID(id)
	if err != nil {
		return nil, err
	}

	// Convert pointers to values and load components for each group
	app.ComponentGroups = make([]ComponentGroup, len(groups))
	for i, group := range groups {
		app.ComponentGroups[i] = *group

		components, err := r.GetComponentsByGroupID(group.ID)
		if err != nil {
			return nil, err
		}

		// Convert component pointers to values
		app.ComponentGroups[i].Components = make([]Component, len(components))
		for j, comp := range components {
			app.ComponentGroups[i].Components[j] = *comp
		}
	}

	// Load members
	members, err := r.GetMembersByApplicationID(id)
	if err != nil {
		return nil, err
	}

	// Convert member pointers to values
	app.Members = make([]Member, len(members))
	for i, member := range members {
		app.Members[i] = *member
	}

	return app, nil
}

func (r *Repository) GetApplicationState(id string) (*ApplicationState, error) {
	query := `SELECT id, name, updated_at FROM applications WHERE id = $1`

	state := &ApplicationState{}
	err := r.db.QueryRow(query, id).Scan(&state.ID, &state.Name, &state.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("application not found")
	}

	return state, err
}

func (r *Repository) UpdateLastSequence(appID string, sequence int64) error {
	query := `UPDATE applications SET last_sequence = $1, updated_at = $2 WHERE id = $3 AND deleted_at IS NULL`
	result, err := r.db.Exec(query, sequence, time.Now().Unix(), appID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("application not found or deleted: %s", appID)
	}
	return nil
}

func (r *Repository) UpdateApplicationTimestamp(id string) error {
	query := `UPDATE applications SET updated_at = $1 WHERE id = $2`

	_, err := r.db.Exec(query, time.Now().Unix(), id)
	return err
}

func (r *Repository) UpdateApplicationMetadata(id, name string, icon *string) error {
	query := `UPDATE applications SET name = $1, icon = $2, updated_at = $3 WHERE id = $4 AND deleted_at IS NULL`

	result, err := r.db.Exec(query, name, icon, time.Now().Unix(), id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("application not found")
	}

	return nil
}

func (r *Repository) DeleteApplication(id string) error {
	query := `UPDATE applications SET deleted_at = $1 WHERE id = $2`

	result, err := r.db.Exec(query, time.Now().Unix(), id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("application not found")
	}

	return nil
}

func (r *Repository) CreateComponentGroup(group *ComponentGroup) error {
	query := `INSERT INTO component_groups (id, application_id, name, index_order)
			  VALUES ($1, $2, $3, $4)
			  ON CONFLICT (id) DO UPDATE SET
			    name = EXCLUDED.name,
			    index_order = EXCLUDED.index_order`

	_, err := r.db.Exec(query, group.ID, group.ApplicationID, group.Name, group.Index)
	return err
}

func (r *Repository) GetComponentGroupsByApplicationID(appID string) ([]*ComponentGroup, error) {
	query := `SELECT id, application_id, name, index_order
			  FROM component_groups WHERE application_id = $1 ORDER BY index_order`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*ComponentGroup
	for rows.Next() {
		group := &ComponentGroup{}
		err := rows.Scan(&group.ID, &group.ApplicationID, &group.Name, &group.Index)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, rows.Err()
}

func (r *Repository) CreateComponent(component *Component) error {
	query := `INSERT INTO components (id, component_group_id, application_id, name, data, index_order)
			  VALUES ($1, $2, $3, $4, $5, $6)
			  ON CONFLICT (id) DO UPDATE SET
			    name = EXCLUDED.name,
			    data = EXCLUDED.data,
			    index_order = EXCLUDED.index_order`

	var dataJSON string
	if component.Data != nil {
		dataBytes, err := json.Marshal(component.Data)
		if err != nil {
			return fmt.Errorf("failed to marshal component data: %w", err)
		}
		dataJSON = string(dataBytes)
	}

	_, err := r.db.Exec(query,
		component.ID,
		component.ComponentGroupID,
		component.ApplicationID,
		component.Name,
		dataJSON,
		component.Index,
	)
	return err
}

func (r *Repository) GetComponentsByGroupID(groupID string) ([]*Component, error) {
	query := `SELECT id, component_group_id, application_id, name, data, index_order
			  FROM components WHERE component_group_id = $1 ORDER BY index_order`

	rows, err := r.db.Query(query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var components []*Component
	for rows.Next() {
		comp := &Component{}
		var dataJSON sql.NullString
		err := rows.Scan(
			&comp.ID,
			&comp.ComponentGroupID,
			&comp.ApplicationID,
			&comp.Name,
			&dataJSON,
			&comp.Index,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON data if present
		if dataJSON.Valid && dataJSON.String != "" {
			if err := json.Unmarshal([]byte(dataJSON.String), &comp.Data); err != nil {
				return nil, fmt.Errorf("failed to unmarshal component data: %w", err)
			}
		}

		components = append(components, comp)
	}

	return components, rows.Err()
}

func (r *Repository) GetComponentsByApplicationID(appID string) ([]*Component, error) {
	query := `SELECT id, component_group_id, application_id, name, data, index_order
			  FROM components WHERE application_id = $1 ORDER BY index_order`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var components []*Component
	for rows.Next() {
		comp := &Component{}
		var dataJSON sql.NullString
		err := rows.Scan(
			&comp.ID,
			&comp.ComponentGroupID,
			&comp.ApplicationID,
			&comp.Name,
			&dataJSON,
			&comp.Index,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSON data if present
		if dataJSON.Valid && dataJSON.String != "" {
			if err := json.Unmarshal([]byte(dataJSON.String), &comp.Data); err != nil {
				return nil, fmt.Errorf("failed to unmarshal component data: %w", err)
			}
		}

		components = append(components, comp)
	}

	return components, rows.Err()
}

func (r *Repository) GetComponentByID(componentID string) (*Component, error) {
	query := `SELECT id, component_group_id, application_id, name, data, index_order
			  FROM components WHERE id = $1`

	comp := &Component{}
	var dataJSON sql.NullString
	err := r.db.QueryRow(query, componentID).Scan(
		&comp.ID,
		&comp.ComponentGroupID,
		&comp.ApplicationID,
		&comp.Name,
		&dataJSON,
		&comp.Index,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("component not found")
	}
	if err != nil {
		return nil, err
	}

	// Parse JSON data if present
	if dataJSON.Valid && dataJSON.String != "" {
		if err := json.Unmarshal([]byte(dataJSON.String), &comp.Data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal component data: %w", err)
		}
	}

	return comp, nil
}

func (r *Repository) UpdateComponentData(componentID string, data map[string]interface{}) error {
	var dataJSON string
	if data != nil {
		dataBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal component data: %w", err)
		}
		dataJSON = string(dataBytes)
	}

	query := `UPDATE components SET data = $1 WHERE id = $2`
	result, err := r.db.Exec(query, dataJSON, componentID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component not found")
	}

	return nil
}

func (r *Repository) UpdateComponentIndex(componentID string, index int) error {
	query := `UPDATE components SET index_order = $1 WHERE id = $2`
	result, err := r.db.Exec(query, index, componentID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component not found")
	}

	return nil
}

func (r *Repository) DeleteComponent(componentID string) error {
	query := `DELETE FROM components WHERE id = $1`
	result, err := r.db.Exec(query, componentID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component not found")
	}

	return nil
}

func (r *Repository) GetComponentGroupByID(groupID string) (*ComponentGroup, error) {
	query := `SELECT id, application_id, name, index_order
			  FROM component_groups WHERE id = $1`

	group := &ComponentGroup{}
	err := r.db.QueryRow(query, groupID).Scan(
		&group.ID,
		&group.ApplicationID,
		&group.Name,
		&group.Index,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("component group not found")
	}
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (r *Repository) UpdateComponentGroupIndex(groupID string, index int) error {
	query := `UPDATE component_groups SET index_order = $1 WHERE id = $2`
	result, err := r.db.Exec(query, index, groupID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component group not found")
	}

	return nil
}

func (r *Repository) UpdateComponentGroup(groupID, name string, index int) error {
	query := `UPDATE component_groups SET name = $1, index_order = $2 WHERE id = $3`
	result, err := r.db.Exec(query, name, index, groupID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component group not found")
	}

	return nil
}

func (r *Repository) DeleteComponentGroup(groupID string) error {
	query := `DELETE FROM component_groups WHERE id = $1`
	result, err := r.db.Exec(query, groupID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("component group not found")
	}

	return nil
}

func (r *Repository) CreateMember(member *Member) error {
	// Conflict target is (application_id, public_key), not id: a re-join
	// (new event, new member.ID) must update the SAME row for that
	// application+key pair rather than insert a duplicate - that's what
	// makes re-joining after expiry an upsert instead of a second row.
	query := `INSERT INTO members (id, application_id, role, public_key, membership_expires_at)
			  VALUES ($1, $2, $3, $4, $5)
			  ON CONFLICT (application_id, public_key) DO UPDATE SET
			    role = EXCLUDED.role, membership_expires_at = EXCLUDED.membership_expires_at`

	_, err := r.db.Exec(query, member.ID, member.ApplicationID, string(member.Role), member.PublicKey, member.MembershipExpiresAt)
	return err
}

func (r *Repository) GetMembersByApplicationID(appID string) ([]*Member, error) {
	query := `SELECT m.id, m.application_id, m.role, m.public_key, u.username, u.avatar_storage_id, m.membership_expires_at
			  FROM members m
			  LEFT JOIN users u ON u.public_key = m.public_key
			  WHERE m.application_id = $1 AND ` + activeMemberPredicate + `
			  ORDER BY m.role`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*Member
	for rows.Next() {
		member := &Member{}
		var roleStr string
		var username sql.NullString
		var avatarStorageID sql.NullString
		var membershipExpiresAt sql.NullInt64

		err := rows.Scan(
			&member.ID,
			&member.ApplicationID,
			&roleStr,
			&member.PublicKey,
			&username,
			&avatarStorageID,
			&membershipExpiresAt,
		)
		if err != nil {
			return nil, err
		}

		member.Role = MemberRole(roleStr)
		if username.Valid {
			member.UserDisplayName = &username.String
		}
		if avatarStorageID.Valid {
			member.UserAvatarStorageID = &avatarStorageID.String
		}
		if membershipExpiresAt.Valid {
			member.MembershipExpiresAt = &membershipExpiresAt.Int64
		}

		members = append(members, member)
	}

	return members, rows.Err()
}

func (r *Repository) GetMemberByID(memberID string) (*Member, error) {
	query := `SELECT id, application_id, role, public_key
			  FROM members WHERE id = $1`

	member := &Member{}
	var roleStr string

	err := r.db.QueryRow(query, memberID).Scan(
		&member.ID,
		&member.ApplicationID,
		&roleStr,
		&member.PublicKey,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("member not found")
	}
	if err != nil {
		return nil, err
	}

	member.Role = MemberRole(roleStr)

	return member, nil
}

func (r *Repository) UpdateMemberRole(memberID string, role MemberRole) error {
	query := `UPDATE members SET role = $1 WHERE id = $2`

	result, err := r.db.Exec(query, string(role), memberID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("member not found")
	}

	return nil
}

func (r *Repository) DeleteMember(memberID string) error {
	query := `DELETE FROM members WHERE id = $1`

	result, err := r.db.Exec(query, memberID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("member not found")
	}

	return nil
}

// GetMemberByPublicKey is used by executeMemberRemoved/executeMemberRoleChanged
// (event_service.go) to resolve a member ID before acting on it - so an
// already-expired member looks not-found there and those actions fail with
// "member not found" instead of a second, unfiltered lookup path. Known
// ceiling, acceptable for #117: nothing outside a scheduler is expected to
// remove/role-change an expired member anyway.
func (r *Repository) GetMemberByPublicKey(appID, publicKey string) (*Member, error) {
	query := `SELECT m.id, m.application_id, m.role, m.public_key
			  FROM members m WHERE m.application_id = $1 AND m.public_key = $2 AND ` + activeMemberPredicate

	member := &Member{}
	var roleStr string

	err := r.db.QueryRow(query, appID, publicKey).Scan(
		&member.ID,
		&member.ApplicationID,
		&roleStr,
		&member.PublicKey,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("member not found")
	}
	if err != nil {
		return nil, err
	}

	member.Role = MemberRole(roleStr)

	return member, nil
}

func (r *Repository) GetApplicationsByMemberPublicKey(publicKey string) ([]*Application, error) {
	query := `SELECT DISTINCT a.id, a.name, a.icon, a.space_public_key, a.space_id, a.created_at, a.updated_at, a.last_sequence
			  FROM applications a
			  INNER JOIN members m ON a.id = m.application_id
			  WHERE m.public_key = $1 AND a.deleted_at IS NULL AND ` + activeMemberPredicate + `
			  ORDER BY a.created_at DESC`

	rows, err := r.db.Query(query, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applications []*Application
	for rows.Next() {
		app := &Application{}
		var lastSequence sql.NullInt64
		var spaceID sql.NullString
		err := rows.Scan(&app.ID, &app.Name, &app.Icon, &app.SpacePublicKey, &spaceID, &app.CreatedAt, &app.UpdatedAt, &lastSequence)
		if err != nil {
			return nil, err
		}
		if lastSequence.Valid {
			app.LastSequence = &lastSequence.Int64
		}
		if spaceID.Valid {
			app.SpaceID = &spaceID.String
		}

		// Load component groups for this application
		groups, err := r.GetComponentGroupsByApplicationID(app.ID)
		if err != nil {
			return nil, err
		}

		// Convert pointers to values and load components for each group
		app.ComponentGroups = make([]ComponentGroup, len(groups))
		for i, group := range groups {
			app.ComponentGroups[i] = *group

			components, err := r.GetComponentsByGroupID(group.ID)
			if err != nil {
				return nil, err
			}

			// Convert component pointers to values
			app.ComponentGroups[i].Components = make([]Component, len(components))
			for j, comp := range components {
				app.ComponentGroups[i].Components[j] = *comp
			}
		}

		// Load members
		members, err := r.GetMembersByApplicationID(app.ID)
		if err != nil {
			return nil, err
		}

		// Convert member pointers to values
		app.Members = make([]Member, len(members))
		for i, member := range members {
			app.Members[i] = *member
		}

		applications = append(applications, app)
	}

	return applications, rows.Err()
}

func (r *Repository) GetAppVersionsByMemberPublicKey(publicKey string) (map[string]AppVersionInfo, error) {
	query := `SELECT DISTINCT a.id, a.last_sequence
			  FROM applications a
			  INNER JOIN members m ON a.id = m.application_id
			  WHERE m.public_key = $1 AND a.deleted_at IS NULL AND ` + activeMemberPredicate

	rows, err := r.db.Query(query, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]AppVersionInfo)
	for rows.Next() {
		var id string
		var lastSequence sql.NullInt64
		if err := rows.Scan(&id, &lastSequence); err != nil {
			return nil, err
		}
		info := AppVersionInfo{}
		if lastSequence.Valid {
			info.LastSequence = &lastSequence.Int64
		}
		result[id] = info
	}
	return result, rows.Err()
}

func (r *Repository) IsMember(appID, publicKey string) (bool, error) {
	query := `SELECT COUNT(*) FROM members m WHERE m.application_id = $1 AND m.public_key = $2 AND ` + activeMemberPredicate

	var count int
	err := r.db.QueryRow(query, appID, publicKey).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *Repository) GetMemberCount(appID string) (int, error) {
	query := `SELECT COUNT(*) FROM members m WHERE m.application_id = $1 AND ` + activeMemberPredicate

	var count int
	err := r.db.QueryRow(query, appID).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
