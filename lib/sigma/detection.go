package sigma

import (
	"sigmai/lib/sigma/condition"
	"sigmai/lib/sigma/search"
)

type Detection struct {
	Searches  map[string]search.Searches `yaml:",inline,omitempty"`
	TimeFrame string                     `yaml:",omitempty"`
	Condition condition.Condition        `yaml:",omitempty"`
}
