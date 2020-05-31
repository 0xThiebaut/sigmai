package api

import (
	"github.com/rs/zerolog"
	"sigmai/lib/sources/misp/api/workers"
	"sigmai/lib/sources/misp/lib/event"
	"sync"
)

// This has workers
type API interface {
	Events() (chan *event.Event, error)
	Error() error
}

type api struct {
	workers []workers.Worker
	err     error
}

func New(o *Options, l zerolog.Logger) (API, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	ws := make([]workers.Worker, o.Workers)
	for i, _ := range ws {
		if w, err := workers.New(o.WorkerOptions, l); err != nil {
			return nil, err
		} else {
			ws[i] = w
		}
	}
	return &api{workers: ws}, nil
}

func (a *api) Error() error {
	return a.err
}

func (a *api) Events() (chan *event.Event, error) {
	events, bare := make(chan *event.Event), make(chan *event.Event)
	var wg sync.WaitGroup
	// Use the first worker to retrieve events
	go func() {
		// Close the channel when the worker has finished returning the bare events
		defer close(bare)
		w := a.workers[0]
		// Send each available event into the bare channel for enrichment
		for e := range w.Events() {
			bare <- e
		}
		if err := w.Error(); err != nil {
			a.err = err
		}
	}()
	// Start all workers except the first to enrich the events.
	// Using the first worker will drastically delay the enrichment of the first event.
	// This event would get attributed to the worker which is already processing all bare events first.
	for _, w := range a.workers[1:] {
		// Wait for the worker to finish
		wg.Add(1)
		// Launch the workers
		go func(w workers.Worker) {
			// Release the worker when done
			defer wg.Done()
			// Return the enriched events
			for e := range w.Enrich(bare) {
				events <- e
			}
			if err := w.Error(); err != nil {
				a.err = err
			}
		}(w)
	}
	// Start the closure routine
	go func() {
		// Close the return channel when all workers are done
		defer close(events)
		// Wait for the workers to release
		wg.Wait()
	}()
	return events, nil
}
