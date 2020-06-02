package directory

import (
	"errors"
	"fmt"
	"github.com/0xThiebaut/sigmai/lib/sigma"
	"github.com/0xThiebaut/sigmai/lib/targets"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v2"
	"os"
	"path"
)

type directory struct {
	Path string
	log  zerolog.Logger
}

// New returns a new Target saving the Sigma rules as files into a directory.
func New(options *Options, l zerolog.Logger) targets.Target {
	return &directory{Path: options.Path, log: l}
}

func (d *directory) Process(rules []*sigma.Rule) error {
	// No rules, no problem
	if len(rules) < 0 {
		return nil
	}
	// Ensure the path is specified
	if len(d.Path) == 0 {
		return errors.New("missing directory path")
	}
	// Ensure the path is a directory
	if i, err := os.Stat(d.Path); err != nil {
		return err
	} else if !i.IsDir() {
		return fmt.Errorf("'%s' is not a directory", d.Path)
	}
	f := rules[0].Id + ".yml"
	p := path.Join(d.Path, f)
	w, err := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer w.Close()
	e := yaml.NewEncoder(w)
	for _, r := range rules {
		if err := e.Encode(r); err != nil {
			return err
		}
	}
	d.log.Info().Str("rule", rules[0].Id).Msg("saved Sigma rule")
	return nil
}

type Options struct {
	// Path is a directory's path into which the rules should be saved.
	// The directory must exist, files might be overwritten.
	Path string
}
