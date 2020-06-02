package sigma

import "github.com/0xThiebaut/sigmai/lib/sigma/field"

type Rule struct {
	Action         Action         `yaml:",omitempty"`
	Title          string         `yaml:",omitempty"`
	Id             string         `yaml:",omitempty"`
	Related        []Relationship `yaml:",omitempty"`
	Status         Status         `yaml:",omitempty"`
	Description    string         `yaml:",omitempty"`
	Author         string         `yaml:",omitempty"`
	References     []string       `yaml:",omitempty"`
	LogSource      LogSource      `yaml:",omitempty"`
	Detection      Detection      `yaml:",omitempty"`
	Fields         []field.Field  `yaml:",omitempty"`
	FalsePositives []string       `yaml:",omitempty"`
	Level          Level          `yaml:",omitempty"`
	Tags           []string       `yaml:",omitempty"`
}

type Action string

const (
	ActionGlobal Action = "global"
	ActionRepeat Action = "repeat"
	ActionReset  Action = "reset"
)

type Status string

const (
	StatusExperimental Status = "experimental"
	StatusTesting      Status = "testing"
	StatusStable       Status = "stable"
)

type Level string

const (
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)
