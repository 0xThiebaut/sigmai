package sources

import (
	"github.com/0xThiebaut/sigmai/lib/sigma"
)

// Source is an abstraction representing an origin generating Sigma rules.
type Source interface {
	Rules() (chan []*sigma.Rule, error)
	Error() error
}
