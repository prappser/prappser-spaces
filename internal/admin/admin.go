// Package admin is the space operator's metadata-only view of the accounts on
// this space. It is unrelated to the app-level admin member role.
package admin

type Overview struct {
	Limits   Limits            `json:"limits"`
	Accounts []AccountOverview `json:"accounts"`
}

type Limits struct {
	AccountQuotaBytes int64 `json:"accountQuotaBytes"`
	MaxAppsPerAccount int   `json:"maxAppsPerAccount"`
}

type AccountOverview struct {
	PublicKey    string `json:"publicKey"`
	Username     string `json:"username"`
	Role         string `json:"role"`
	CreatedAt    int64  `json:"createdAt"`
	LastActiveAt *int64 `json:"lastActiveAt"`
	StorageBytes int64  `json:"storageBytes"`
	FileCount    int64  `json:"fileCount"`
	OwnedApps    int64  `json:"ownedApps"`
}
