package sharinggroup

import "github.com/0xThiebaut/sigmai/lib/sources/misp/lib/organisation"

type Group struct {
	ID                 string `json:",omitempty"`
	Name               string `json:",omitempty"`
	Releasability      string `json:",omitempty"`
	Description        string `json:",omitempty"`
	UUID               string
	OrganisationUUID   string           `json:"organisation_uuid,omitempty"`
	OrgID              string           `json:"org_id,omitempty"`
	SyncUserID         string           `json:"sync_user_id,omitempty"`
	Active             bool             `json:",omitempty"`
	Created            string           `json:",omitempty"`
	Modified           string           `json:",omitempty"`
	Local              bool             `json:",omitempty"`
	Roaming            bool             `json:",omitempty"`
	Organisation       organisation.Org `json:",omitempty"`
	SharingGroupOrg    []interface{}    `json:"sharing_group_org,omitempty"`
	SharingGroupServer []interface{}    `json:"sharing_group_server,omitempty"`
}
