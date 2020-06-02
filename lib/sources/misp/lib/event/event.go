package event

import (
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/attribute"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/object"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/organisation"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/sharinggroup"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/tag"
)

type Event struct {
	UUID               string
	ID                 string
	Published          bool
	Info               string
	ThreatLevelId      ThreatLevel `json:"threat_level_id"`
	Analysis           AnalysisLevel
	Date               string
	Timestamp          string
	PublishedTimestamp string `json:"published_timestamp"`
	OrgId              string `json:"org_id"`
	OrgcId             string `json:"orgc_id"`
	AttributeCount     string `json:"attribute_count"`
	Distribution       Distribution
	SharingGroupId     string `json:"sharing_group_id"`
	ExtendsUUID        string `json:"extends_uuid"`
	ProposalEmailLock  bool   `json:"proposal_email_lock"`
	Locked             bool
	DisableCorrelation bool   `json:"disable_correlation"`
	EventCreatorEmail  string `json:"event_creator_email"`
	Org                organisation.Org
	Orgc               organisation.Orgc
	SharingGroup       sharinggroup.Group
	Attribute          []*attribute.Attribute
	ShadowAttribute    []*attribute.ShadowAttribute
	RelatedEvent       []Relation
	Galaxy             []interface{}
	Object             []*object.Object
	Tag                []tag.Tag
}

type Relation struct {
	Event Event
}

type ThreatLevel string

const (
	ThreatLevelUndefined ThreatLevel = "4"
	ThreatLevelLow       ThreatLevel = "3"
	ThreatLevelMedium    ThreatLevel = "2"
	ThreatLevelHigh      ThreatLevel = "1"
)

type AnalysisLevel string

const (
	AnalysisLevelInitial  AnalysisLevel = "0"
	AnalysisLevelOngoing  AnalysisLevel = "1"
	AnalysisLevelComplete AnalysisLevel = "2"
)

type Distribution string

const (
	DistributionOrganisation         Distribution = "0"
	DistributionCommunity            Distribution = "1"
	DistributionConnectedCommunities Distribution = "2"
	DistributionAllCommunities       Distribution = "3"
	DistributionSharingGroup         Distribution = "4"
)
