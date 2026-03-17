package application

type ApplicationRepository interface {
	CreateApplication(app *Application) error
	GetApplicationByID(id string) (*Application, error)
	GetApplicationState(id string) (*ApplicationState, error)
	UpdateApplicationTimestamp(id string) error
	DeleteApplication(id string) error
	
	CreateComponentGroup(group *ComponentGroup) error
	GetComponentGroupsByApplicationID(appID string) ([]*ComponentGroup, error)
	
	CreateComponent(component *Component) error
	GetComponentByID(componentID string) (*Component, error)
	GetComponentsByGroupID(groupID string) ([]*Component, error)
	GetComponentsByApplicationID(appID string) ([]*Component, error)
	UpdateComponentData(componentID string, data map[string]interface{}) error
	UpdateComponentIndex(componentID string, index int) error
	DeleteComponent(componentID string) error

	GetComponentGroupByID(groupID string) (*ComponentGroup, error)
	UpdateComponentGroupIndex(groupID string, index int) error
	DeleteComponentGroup(groupID string) error
	
	CreateMember(member *Member) error
	GetMembersByApplicationID(appID string) ([]*Member, error)
	GetMemberByID(memberID string) (*Member, error)
	GetMemberByPublicKey(appID, publicKey string) (*Member, error)
	UpdateMember(member *Member) error
	UpdateMemberAvatarByPublicKey(publicKey string, avatarStorageID *string) error
	DeleteMember(memberID string) error

	// Invitation-related methods
	GetApplicationsByMemberPublicKey(publicKey string) ([]*Application, error)
	// GetAppVersionsByMemberPublicKey returns a lightweight map of app ID → version info
	// for all non-deleted apps the user is a member of. Used by the poll path to avoid
	// full N+1 application loads.
	GetAppVersionsByMemberPublicKey(publicKey string) (map[string]AppVersionInfo, error)
	IsMember(appID, publicKey string) (bool, error)
	GetMemberCount(appID string) (int, error)
	UpdateApplicationMetadata(id, name string, icon *string) error
	// UpdateLastSequence stores the last processed sequence number for drift detection.
	UpdateLastSequence(appID string, sequence int64) error
}
