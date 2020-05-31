package targets

import "sigmai/lib/sigma"

// Target is an abstraction defining where to send the generated Sigma rules.
type Target interface {
	// Process takes a slice of Sigma rules and handles them accordingly to the target's behaviour.
	Process(rules []*sigma.Rule) error
}
