package stdout

import (
	"github.com/0xThiebaut/sigmai/lib/sigma"
	"github.com/0xThiebaut/sigmai/lib/targets"
	"gopkg.in/yaml.v2"
	"os"
)

type stdout struct {
	Encoder *yaml.Encoder
}

// New returns a new Target outputting the Sigma rules to stdout.
func New() targets.Target {
	return &stdout{Encoder: yaml.NewEncoder(os.Stdout)}
}

func (s *stdout) Process(rules []*sigma.Rule) error {
	for _, r := range rules {
		if err := s.Encoder.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
