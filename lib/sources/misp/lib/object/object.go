package object

import "github.com/0xThiebaut/sigmai/lib/sources/misp/lib/attribute"

type Object struct {
	UUID            string
	ID              string
	Name            string
	MetaCategory    string `json:"meta-category"`
	Description     string
	TemplateUUID    string `json:"template_uuid"`
	TemplateVersion string `json:"template_version"`
	EventID         string `json:"event_id"`
	Timestamp       string
	Distribution    Distribution
	SharingGroupId  string `json:"sharing_group_id"`
	Comment         string
	Deleted         bool
	Attribute       []*attribute.Attribute
}

type Distribution string

const (
	DistributionOrganisation         Distribution = "0"
	DistributionCommunity            Distribution = "1"
	DistributionConnectedCommunities Distribution = "2"
	DistributionAllCommunities       Distribution = "3"
	DistributionSharingGroup         Distribution = "4"
)
