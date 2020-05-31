package sharinggroup

type Server struct {
	ID             string
	SharingGroupID string `json:"sharing_group_id"`
	ServerID       string `json:"server_id"`
	AllOrgs        bool   `json:"all_orgs"`
	Server         interface{}
}
