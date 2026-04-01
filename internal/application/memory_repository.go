package application

import (
	"fmt"
	"sort"
	"time"
)

type MemoryRepository struct {
	applications    map[string]*Application
	componentGroups map[string]*ComponentGroup
	components      map[string]*Component
	members         map[string]*Member
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		applications:    make(map[string]*Application),
		componentGroups: make(map[string]*ComponentGroup),
		components:      make(map[string]*Component),
		members:         make(map[string]*Member),
	}
}

func (r *MemoryRepository) CreateApplication(app *Application) error {
	r.applications[app.ID] = app
	return nil
}

func (r *MemoryRepository) GetApplicationByID(id string) (*Application, error) {
	app, exists := r.applications[id]
	if !exists {
		return nil, fmt.Errorf("application not found")
	}

	if app.DeletedAt != nil {
		return nil, fmt.Errorf("application not found")
	}

	// Create a copy and load component groups
	result := *app
	groups, err := r.GetComponentGroupsByApplicationID(id)
	if err != nil {
		return nil, err
	}

	result.ComponentGroups = make([]ComponentGroup, len(groups))
	for i, group := range groups {
		result.ComponentGroups[i] = *group

		components, err := r.GetComponentsByGroupID(group.ID)
		if err != nil {
			return nil, err
		}

		result.ComponentGroups[i].Components = make([]Component, len(components))
		for j, comp := range components {
			result.ComponentGroups[i].Components[j] = *comp
		}
	}

	// Load members
	members, err := r.GetMembersByApplicationID(id)
	if err != nil {
		return nil, err
	}

	result.Members = make([]Member, len(members))
	for i, member := range members {
		result.Members[i] = *member
	}

	return &result, nil
}

func (r *MemoryRepository) GetApplicationState(id string) (*ApplicationState, error) {
	app, exists := r.applications[id]
	if !exists {
		return nil, fmt.Errorf("application not found")
	}

	return &ApplicationState{
		ID:        app.ID,
		Name:      app.Name,
		UpdatedAt: app.UpdatedAt,
	}, nil
}

func (r *MemoryRepository) UpdateApplicationTimestamp(id string) error {
	app, exists := r.applications[id]
	if !exists {
		return fmt.Errorf("application not found")
	}

	app.UpdateTimestamp()
	return nil
}

func (r *MemoryRepository) UpdateApplicationMetadata(id, name string, icon *string) error {
	app, exists := r.applications[id]
	if !exists {
		return fmt.Errorf("application not found")
	}

	if app.DeletedAt != nil {
		return fmt.Errorf("application not found")
	}

	app.Name = name
	app.Icon = icon
	app.UpdateTimestamp()
	return nil
}

func (r *MemoryRepository) DeleteApplication(id string) error {
	app, exists := r.applications[id]
	if !exists {
		return fmt.Errorf("application not found")
	}

	// Soft-delete: keep all associations alive so events can still be delivered
	now := time.Now().Unix()
	app.DeletedAt = &now

	return nil
}

func (r *MemoryRepository) CreateComponentGroup(group *ComponentGroup) error {
	r.componentGroups[group.ID] = group
	return nil
}

func (r *MemoryRepository) GetComponentGroupsByApplicationID(appID string) ([]*ComponentGroup, error) {
	var result []*ComponentGroup
	for _, group := range r.componentGroups {
		if group.ApplicationID == appID {
			result = append(result, group)
		}
	}

	// Sort by index
	sort.Slice(result, func(i, j int) bool {
		return result[i].Index < result[j].Index
	})

	return result, nil
}

func (r *MemoryRepository) CreateComponent(component *Component) error {
	r.components[component.ID] = component
	return nil
}

func (r *MemoryRepository) GetComponentsByGroupID(groupID string) ([]*Component, error) {
	var result []*Component
	for _, comp := range r.components {
		if comp.ComponentGroupID == groupID {
			result = append(result, comp)
		}
	}

	// Sort by index
	sort.Slice(result, func(i, j int) bool {
		return result[i].Index < result[j].Index
	})

	return result, nil
}

func (r *MemoryRepository) GetComponentsByApplicationID(appID string) ([]*Component, error) {
	var result []*Component
	for _, comp := range r.components {
		if comp.ApplicationID == appID {
			result = append(result, comp)
		}
	}

	// Sort by index
	sort.Slice(result, func(i, j int) bool {
		return result[i].Index < result[j].Index
	})

	return result, nil
}

func (r *MemoryRepository) GetComponentByID(componentID string) (*Component, error) {
	comp, exists := r.components[componentID]
	if !exists {
		return nil, fmt.Errorf("component not found")
	}
	return comp, nil
}

func (r *MemoryRepository) UpdateComponentData(componentID string, data map[string]interface{}) error {
	comp, exists := r.components[componentID]
	if !exists {
		return fmt.Errorf("component not found")
	}
	comp.Data = data
	return nil
}

func (r *MemoryRepository) UpdateComponentIndex(componentID string, index int) error {
	comp, exists := r.components[componentID]
	if !exists {
		return fmt.Errorf("component not found")
	}
	comp.Index = index
	return nil
}

func (r *MemoryRepository) DeleteComponent(componentID string) error {
	_, exists := r.components[componentID]
	if !exists {
		return fmt.Errorf("component not found")
	}
	delete(r.components, componentID)
	return nil
}

func (r *MemoryRepository) GetComponentGroupByID(groupID string) (*ComponentGroup, error) {
	group, exists := r.componentGroups[groupID]
	if !exists {
		return nil, fmt.Errorf("component group not found")
	}
	return group, nil
}

func (r *MemoryRepository) UpdateComponentGroupIndex(groupID string, index int) error {
	group, exists := r.componentGroups[groupID]
	if !exists {
		return fmt.Errorf("component group not found")
	}
	group.Index = index
	return nil
}

func (r *MemoryRepository) UpdateComponentGroup(groupID, name string, index int) error {
	group, exists := r.componentGroups[groupID]
	if !exists {
		return fmt.Errorf("component group not found")
	}
	group.Name = name
	group.Index = index
	return nil
}

func (r *MemoryRepository) DeleteComponentGroup(groupID string) error {
	_, exists := r.componentGroups[groupID]
	if !exists {
		return fmt.Errorf("component group not found")
	}

	// Delete associated components
	var componentsToDelete []string
	for compID, comp := range r.components {
		if comp.ComponentGroupID == groupID {
			componentsToDelete = append(componentsToDelete, compID)
		}
	}
	for _, compID := range componentsToDelete {
		delete(r.components, compID)
	}

	delete(r.componentGroups, groupID)
	return nil
}

func (r *MemoryRepository) CreateMember(member *Member) error {
	r.members[member.ID] = member
	return nil
}

func (r *MemoryRepository) GetMembersByApplicationID(appID string) ([]*Member, error) {
	var result []*Member
	for _, member := range r.members {
		if member.ApplicationID == appID {
			result = append(result, member)
		}
	}

	// Sort by role (owner first, then admin, then member, then viewer)
	sort.Slice(result, func(i, j int) bool {
		roleOrder := map[MemberRole]int{
			MemberRoleOwner:  0,
			MemberRoleAdmin:  1,
			MemberRoleMember: 2,
			MemberRoleViewer: 3,
		}
		return roleOrder[result[i].Role] < roleOrder[result[j].Role]
	})

	return result, nil
}

func (r *MemoryRepository) GetMemberByID(memberID string) (*Member, error) {
	member, exists := r.members[memberID]
	if !exists {
		return nil, fmt.Errorf("member not found")
	}
	return member, nil
}

func (r *MemoryRepository) UpdateMember(member *Member) error {
	_, exists := r.members[member.ID]
	if !exists {
		return fmt.Errorf("member not found")
	}
	r.members[member.ID] = member
	return nil
}

func (r *MemoryRepository) UpdateMemberAvatarByPublicKey(publicKey string, avatarStorageID *string) error {
	for _, member := range r.members {
		if member.PublicKey == publicKey {
			member.AvatarStorageID = avatarStorageID
		}
	}
	return nil
}

func (r *MemoryRepository) DeleteMember(memberID string) error {
	_, exists := r.members[memberID]
	if !exists {
		return fmt.Errorf("member not found")
	}
	delete(r.members, memberID)
	return nil
}

// GetMemberByPublicKey returns a member by public key for a specific application
func (r *MemoryRepository) GetMemberByPublicKey(appID, publicKey string) (*Member, error) {
	for _, member := range r.members {
		if member.ApplicationID == appID && member.PublicKey == publicKey {
			return member, nil
		}
	}
	return nil, fmt.Errorf("member not found")
}

// GetApplicationsByMemberPublicKey returns all applications where the user is a member
func (r *MemoryRepository) GetApplicationsByMemberPublicKey(publicKey string) ([]*Application, error) {
	// First, find all applications where user is a member
	appIDSet := make(map[string]bool)
	for _, member := range r.members {
		if member.PublicKey == publicKey {
			appIDSet[member.ApplicationID] = true
		}
	}

	// Get full application details for each, skipping soft-deleted apps
	var result []*Application
	for appID := range appIDSet {
		app, err := r.GetApplicationByID(appID)
		if err != nil {
			continue // Skip if app not found
		}
		if app.DeletedAt != nil {
			continue // Skip soft-deleted apps
		}
		result = append(result, app)
	}

	// Sort by creation time (newest first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})

	return result, nil
}

// GetAppVersionsByMemberPublicKey returns a lightweight map of app ID → version info
// for all non-deleted apps the user is a member of.
func (r *MemoryRepository) GetAppVersionsByMemberPublicKey(publicKey string) (map[string]AppVersionInfo, error) {
	result := make(map[string]AppVersionInfo)
	for _, member := range r.members {
		if member.PublicKey != publicKey {
			continue
		}
		app, exists := r.applications[member.ApplicationID]
		if !exists || app.DeletedAt != nil {
			continue
		}
		result[app.ID] = AppVersionInfo{
			LastSequence: app.LastSequence,
		}
	}
	return result, nil
}

// IsMember checks if a user is a member of an application
func (r *MemoryRepository) IsMember(appID, publicKey string) (bool, error) {
	for _, member := range r.members {
		if member.ApplicationID == appID && member.PublicKey == publicKey {
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryRepository) UpdateLastSequence(appID string, sequence int64) error {
	app, exists := r.applications[appID]
	if !exists || app.DeletedAt != nil {
		return fmt.Errorf("application not found or deleted: %s", appID)
	}
	app.LastSequence = &sequence
	app.UpdateTimestamp()
	r.applications[appID] = app
	return nil
}

// GetMemberCount returns the number of members in an application
func (r *MemoryRepository) GetMemberCount(appID string) (int, error) {
	count := 0
	for _, member := range r.members {
		if member.ApplicationID == appID {
			count++
		}
	}
	return count, nil
}