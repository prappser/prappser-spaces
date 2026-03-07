package application

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateApplication(app *Application) error {
	query := `INSERT INTO applications (id, name, icon, server_public_key, created_at, updated_at)
			  VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.Exec(query, app.ID, app.Name, app.Icon, app.ServerPublicKey, app.CreatedAt, app.UpdatedAt)
	return err
}

func (r *Repository) GetApplicationByID(id string) (*Application, error) {
	query := `SELECT id, name, icon, server_public_key, created_at, updated_at
			  FROM applications WHERE id = $1 AND deleted_at IS NULL`

	app := &Application{}
	err := r.db.QueryRow(query, id).Scan(
		&app.ID, &app.Name, &app.Icon, &app.ServerPublicKey, &app.CreatedAt, &app.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("application not found")
	}
	if err != nil {
		return nil, err
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

func (r *Repository) UpdateApplicationTimestamp(id string) error {
	query := `UPDATE applications SET updated_at = $1 WHERE id = $2`

	_, err := r.db.Exec(query, time.Now().Unix(), id)
	return err
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
			  VALUES ($1, $2, $3, $4)`

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
			  VALUES ($1, $2, $3, $4, $5, $6)`

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
	query := `INSERT INTO members (id, application_id, name, role, public_key, avatar_storage_id)
			  VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.db.Exec(query, member.ID, member.ApplicationID, member.Name, string(member.Role), member.PublicKey, member.AvatarStorageID)
	return err
}

func (r *Repository) GetMembersByApplicationID(appID string) ([]*Member, error) {
	query := `SELECT id, application_id, name, role, public_key, avatar_storage_id
			  FROM members WHERE application_id = $1 ORDER BY role, name`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*Member
	for rows.Next() {
		member := &Member{}
		var roleStr string

		err := rows.Scan(
			&member.ID,
			&member.ApplicationID,
			&member.Name,
			&roleStr,
			&member.PublicKey,
			&member.AvatarStorageID,
		)
		if err != nil {
			return nil, err
		}

		member.Role = MemberRole(roleStr)

		members = append(members, member)
	}

	return members, rows.Err()
}

func (r *Repository) GetMemberByID(memberID string) (*Member, error) {
	query := `SELECT id, application_id, name, role, public_key, avatar_storage_id
			  FROM members WHERE id = $1`

	member := &Member{}
	var roleStr string

	err := r.db.QueryRow(query, memberID).Scan(
		&member.ID,
		&member.ApplicationID,
		&member.Name,
		&roleStr,
		&member.PublicKey,
		&member.AvatarStorageID,
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

func (r *Repository) UpdateMember(member *Member) error {
	query := `UPDATE members SET name = $1, role = $2, public_key = $3, avatar_storage_id = $4
			  WHERE id = $5`

	result, err := r.db.Exec(query, member.Name, string(member.Role), member.PublicKey, member.AvatarStorageID, member.ID)
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

func (r *Repository) GetMemberByPublicKey(appID, publicKey string) (*Member, error) {
	query := `SELECT id, application_id, name, role, public_key, avatar_storage_id
			  FROM members WHERE application_id = $1 AND public_key = $2`

	member := &Member{}
	var roleStr string

	err := r.db.QueryRow(query, appID, publicKey).Scan(
		&member.ID,
		&member.ApplicationID,
		&member.Name,
		&roleStr,
		&member.PublicKey,
		&member.AvatarStorageID,
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
	query := `SELECT DISTINCT a.id, a.name, a.icon, a.server_public_key, a.created_at, a.updated_at
			  FROM applications a
			  INNER JOIN members m ON a.id = m.application_id
			  WHERE m.public_key = $1 AND a.deleted_at IS NULL
			  ORDER BY a.created_at DESC`

	rows, err := r.db.Query(query, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applications []*Application
	for rows.Next() {
		app := &Application{}
		err := rows.Scan(&app.ID, &app.Name, &app.Icon, &app.ServerPublicKey, &app.CreatedAt, &app.UpdatedAt)
		if err != nil {
			return nil, err
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

func (r *Repository) IsMember(appID, publicKey string) (bool, error) {
	query := `SELECT COUNT(*) FROM members WHERE application_id = $1 AND public_key = $2`

	var count int
	err := r.db.QueryRow(query, appID, publicKey).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *Repository) GetMemberCount(appID string) (int, error) {
	query := `SELECT COUNT(*) FROM members WHERE application_id = $1`

	var count int
	err := r.db.QueryRow(query, appID).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
