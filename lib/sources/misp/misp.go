package misp

import (
	"github.com/rs/zerolog"
	"sigmai/lib/sigma"
	"sigmai/lib/sources"
	"sigmai/lib/sources/misp/api"
	"sigmai/lib/sources/misp/converter"
)

type misp struct {
	API api.API
	err error
	log zerolog.Logger
}

type Options api.Options

func New(o *Options, l zerolog.Logger) (sources.Source, error) {
	ao := api.Options(*o)
	a, err := api.New(&ao, l)
	if err != nil {
		return nil, err
	}
	return &misp{API: a, log: l}, nil
}

func (m *misp) Rules() (chan []*sigma.Rule, error) {
	// Get the events as a stream
	events, err := m.API.Events()
	if err != nil {
		return nil, err
	}
	rules := make(chan []*sigma.Rule)
	c := converter.New(m.log)
	go func() {
		defer close(rules)
		for e := range events {
			r := c.Convert(e)
			rules <- r
		}
		if err := m.API.Error(); err != nil {
			m.err = err
		}
	}()
	return rules, nil
}

func (m *misp) Error() error {
	return m.err
}
