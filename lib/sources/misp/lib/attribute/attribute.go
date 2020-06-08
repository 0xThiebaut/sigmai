package attribute

import (
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/organisation"
)

type Attribute struct {
	UUID             string
	ID               string
	Type             Type
	Category         string
	ToIDS            bool   `json:"to_ids"`
	EventId          string `json:"event_id"`
	Distribution     Distribution
	TimeStamp        string
	Comment          string
	SharingGroupId   string `json:"sharing_group_id"`
	Deleted          bool
	Data             string
	RelatedAttribute []Attribute       `json:",omitempty"`
	ShadowAttribute  []ShadowAttribute `json:",omitempty"`
	Value            string
	ObjectID         string `json:"object_id"`
}

type Distribution string

const (
	DistributionOrganisation         Distribution = "0"
	DistributionCommunity            Distribution = "1"
	DistributionConnectedCommunities Distribution = "2"
	DistributionAllCommunities       Distribution = "3"
	DistributionSharingGroup         Distribution = "4"
	DistributionInherit              Distribution = "5"
)

type ShadowAttribute struct {
	*Attribute
	OldId            string `json:"old_id"`
	OrgId            string `json:"org_id"`
	ProposalToDelete bool   `json:"proposal_to_delete"`
	Org              organisation.Org
}

type Type string

const (
	TypeDomain          Type = "domain"
	TypeDomainIP        Type = "domain|ip"
	TypeEmailDst        Type = "email-dst"
	TypeEmailSrc        Type = "email-src"
	TypeFilename        Type = "filename"
	TypeFilenameImphash Type = "filename|imphash"
	TypeFilenameMD5     Type = "filename|md5"
	TypeFilenameSHA1    Type = "filename|sha1"
	TypeFilenameSHA256  Type = "filename|sha256"
	TypeFilenameSHA384  Type = "filename|sha384"
	TypeFilenameSHA512  Type = "filename|sha512"
	TypeFilenameSSDeep  Type = "filename|ssdeep"
	TypeHostname        Type = "hostname"
	TypeHostnamePort    Type = "hostname|port"
	TypeImphash         Type = "imphash"
	TypeIPDst           Type = "ip-dst"
	TypeIPDstPort       Type = "ip-dst|port"
	TypeIPSrc           Type = "ip-src"
	TypeIPSrcPort       Type = "ip-src|port"
	TypeMD5             Type = "md5"
	TypeMutex           Type = "mutex"
	TypeRegKeyValue     Type = "regkey|value"
	TypeRegKey          Type = "regkey"
	TypeSHA1            Type = "sha1"
	TypeSHA256          Type = "sha256"
	TypeSHA512          Type = "sha512"
	TypeSSDeep          Type = "ssdeep"
	TypeURI             Type = "uri"
	TypeURL             Type = "url"
)
