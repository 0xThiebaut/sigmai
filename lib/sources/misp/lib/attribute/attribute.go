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
	ObjectID         string   `json:"object_id"`
	ObjectRelation   Relation `json:"object_relation,omitempty"`
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
	TypeBIC               Type = "bic"
	TypeBTC               Type = "btc"
	TypeDomain            Type = "domain"
	TypeDomainIP          Type = "domain|ip"
	TypeEmail             Type = "email"
	TypeEmailDst          Type = "email-dst"
	TypeEmailSrc          Type = "email-src"
	TypeEmailSubject      Type = "email-subject"
	TypeFilename          Type = "filename"
	TypeFilenameImphash   Type = "filename|imphash"
	TypeFilenameMD5       Type = "filename|md5"
	TypeFilenameSHA1      Type = "filename|sha1"
	TypeFilenameSHA256    Type = "filename|sha256"
	TypeFilenameSHA384    Type = "filename|sha384"
	TypeFilenameSHA512    Type = "filename|sha512"
	TypeFilenameSSDeep    Type = "filename|ssdeep"
	TypeHostname          Type = "hostname"
	TypeHostnamePort      Type = "hostname|port"
	TypeImphash           Type = "imphash"
	TypeIPDst             Type = "ip-dst"
	TypeIPDstPort         Type = "ip-dst|port"
	TypeIPSrc             Type = "ip-src"
	TypeIPSrcPort         Type = "ip-src|port"
	TypeJarmFingerprint   Type = "jarm-fingerprint"
	TypeJA3FingerprintMD5 Type = "ja3-fingerprint-md5"
	TypeMalwareSample     Type = "malware-sample"
	TypeMD5               Type = "md5"
	TypeMutex             Type = "mutex"
	TypeRegKeyValue       Type = "regkey|value"
	TypeRegKey            Type = "regkey"
	TypeSHA1              Type = "sha1"
	TypeSHA256            Type = "sha256"
	TypeSHA512            Type = "sha512"
	TypeSnort             Type = "snort"
	TypeSSDeep            Type = "ssdeep"
	TypeText              Type = "text"
	TypeURI               Type = "uri"
	TypeURL               Type = "url"
	TypeVulnerability     Type = "vulnerability"
	TypeYara              Type = "yara"
)

type Relation string

const (
	RelationAuthentihash      Relation = "authentihash"
	RelationCommandLine       Relation = "command-line"
	RelationDomain            Relation = "domain"
	RelationFileName          Relation = "filename"
	RelationHostname          Relation = "hostname"
	RelationImage             Relation = "image"
	RelationInternalFileName  Relation = "internal-filename"
	RelationImpfuzzy          Relation = "impfuzzy"
	RelationImphash           Relation = "imphash"
	RelationIP                Relation = "ip"
	RelationKey               Relation = "key"
	RelationMethod            Relation = "method"
	RelationMD5               Relation = "md5"
	RelationOriginalFileName  Relation = "original-filename"
	RelationSHA1              Relation = "sha1"
	RelationSHA256            Relation = "sha256"
	RelationSHA512            Relation = "sha512"
	RelationShortenedUrl      Relation = "shortened-url"
	RelationSSDeep            Relation = "ssdeep"
	RelationMalwareSample     Relation = "malware-sample"
	RelationName              Relation = "name"
	RelationParentImage       Relation = "parent-image"
	RelationParentProcessName Relation = "parent-process-name"
	RelationPort              Relation = "port"
	RelationRedirectUrl       Relation = "redirect-url"
	RelationSuricata          Relation = "suricata"
	RelationUri               Relation = "uri"
	RelationUrl               Relation = "url"
	RelationUrlRedirect       Relation = "url-redirect"
	RelationValue             Relation = "value"
	RelationVhash             Relation = "vhash"
	RelationYara              Relation = "yara"
)
