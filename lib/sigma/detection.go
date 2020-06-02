package sigma

import (
	"github.com/0xThiebaut/sigmai/lib/sigma/condition"
	"github.com/0xThiebaut/sigmai/lib/sigma/search"
)

type Detection struct {
	Searches  map[string]search.Searches `yaml:",inline,omitempty"`
	TimeFrame string                     `yaml:",omitempty"`
	Condition condition.Condition        `yaml:",omitempty"`
}
