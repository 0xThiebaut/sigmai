package workers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/attribute"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/event"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/object"
	"github.com/rs/zerolog"
	"net/http"
	"net/url"
	"sync"
)

type Worker interface {
	Enrich(events chan *event.Event) chan *event.Event
	Events() chan *event.Event
	Error() error
}

type worker struct {
	Client       *http.Client
	Options      *Options
	mutex        sync.Mutex
	eventURL     string
	objectURL    string
	attributeURL string
	err          error
	log          zerolog.Logger
}

func New(o *Options, l zerolog.Logger) (Worker, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	eu, err := u.Parse("/events/restSearch")
	if err != nil {
		return nil, err
	}
	ou, err := u.Parse("/objects/restSearch")
	if err != nil {
		return nil, err
	}
	au, err := u.Parse("/attributes/restSearch")
	if err != nil {
		return nil, err
	}
	// Create a new transport
	t := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure}}
	// Create a new client
	c := &http.Client{Transport: t}
	return &worker{
		Options:      o,
		Client:       c,
		eventURL:     eu.String(),
		objectURL:    ou.String(),
		attributeURL: au.String(),
		log:          l,
	}, nil
}

func (w *worker) Error() error {
	return w.err
}

func (w *worker) Events() chan *event.Event {
	// Create a result channel
	result := make(chan *event.Event)
	// Launch the event retrieval
	go func() {
		// Close the channel when done
		defer close(result)
		// Lock the worker as we re about to make a request
		w.mutex.Lock()
		// Unlock the worker as soon as we are done
		defer w.mutex.Unlock()
		// Create the event filter
		f := w.Options.EventFilter()
		for page, size, finished := 1, 0, false; !finished; page, size = page+1, 0 {
			// Set the page
			f["page"] = page
			// Convert the filter to JSON
			b, err := json.Marshal(f)
			if err != nil {
				w.err = err
				return
			}
			// Create the request
			req, err := http.NewRequest(http.MethodPost, w.eventURL, bytes.NewReader(b))
			if err != nil {
				w.err = err
				return
			}
			// Authenticate the request
			w.Options.Authorize(req)
			// Perform the request
			resp, err := w.Client.Do(req)
			if err != nil {
				w.err = err
				return
			}
			// Create a new decoder
			dec := json.NewDecoder(resp.Body)
			// Skip the opening tokens
			if err := skip(dec, 3); err != nil {
				_ = resp.Body.Close()
				w.err = err
				return
			}
			// Loop the elements in the array
			for ; dec.More(); size += 1 {
				var re respEvent
				if err := dec.Decode(&re); err != nil {
					_ = resp.Body.Close()
					w.err = err
					return
				}
				result <- re.Event
			}
			// Guess if there could still be events on the next page
			finished = size < w.Options.Buffer
		}
	}()
	return result
}

func skip(dec *json.Decoder, n int) error {
	for i := 0; i < n; i++ {
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}

func (w *worker) Enrich(events chan *event.Event) chan *event.Event {
	// Create a result channel
	result := make(chan *event.Event)
	// Launch the enrichment per event
	go func() {
		// Close the channel when done
		defer close(result)
		// For each event, enrich it and return
		for e := range events {
			// Log any occurring error
			if err := w.enrich(e); err != nil {
				w.err = err
			} else {
				result <- e
			}
		}
	}()
	// Return the result channel
	return result
}

func (w *worker) enrich(e *event.Event) error {
	// Lock and plan an unlock
	w.mutex.Lock()
	defer w.mutex.Unlock()
	// Enrich the objects first
	if err := w.enrichObjects(e); err != nil {
		return err
	}
	// Enrich the attributes afterwards
	if err := w.enrichAttributes(e); err != nil {
		return err
	}
	return nil
}

func (w *worker) enrichObjects(e *event.Event) error {
	// Define the attribute filter
	f := w.Options.ObjectFilter()
	f["eventid"] = e.ID
	// Define the objects
	for page, size, finished := 1, 0, false; !finished; page, size = page+1, 0 {
		// Set the page
		f["page"] = page
		// Convert the filter to JSON
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		// Create the request
		req, err := http.NewRequest(http.MethodPost, w.objectURL, bytes.NewReader(b))
		if err != nil {
			return err
		}
		// Add headers
		w.Options.Authorize(req)
		//Perform the request
		resp, err := w.Client.Do(req)
		if err != nil {
			return err
		}
		// Create a new decoder
		dec := json.NewDecoder(resp.Body)
		// Skip the opening tokens
		if err := skip(dec, 3); err != nil {
			_ = resp.Body.Close()
			return err
		}
		// Loop the objects in the array
		for ; dec.More(); size += 1 {
			var ro respObject
			if err := dec.Decode(&ro); err != nil {
				_ = resp.Body.Close()
				return err
			}
			e.Object = append(e.Object, ro.Object)
		}
		_ = resp.Body.Close()
		// Guess if the next page might still contain objects
		finished = size < w.Options.Buffer
	}
	return nil
}

func (w *worker) enrichAttributes(e *event.Event) error {
	// Define the attribute filter
	f := w.Options.AttributeFilter()
	f["eventid"] = e.ID
	// Define an object cache
	oc := map[string]*object.Object{}
	// Populate the cache
	for _, o := range e.Object {
		oc[o.ID] = o
	}
	// Define the objects
	for page, size, finished := 1, 0, false; !finished; page, size = page+1, 0 {
		// Set the page
		f["page"] = page
		// Convert the filter to JSON
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		// Create the request
		req, err := http.NewRequest(http.MethodPost, w.attributeURL, bytes.NewReader(b))
		if err != nil {
			return err
		}
		// Add headers
		w.Options.Authorize(req)
		//Perform the request
		resp, err := w.Client.Do(req)
		if err != nil {
			return err
		}
		// Create a new decoder
		dec := json.NewDecoder(resp.Body)
		// Skip the opening tokens
		if err := skip(dec, 5); err != nil {
			_ = resp.Body.Close()
			return err
		}
		// Loop the objects in the array
		for ; dec.More(); size += 1 {
			var a attribute.Attribute
			if err := dec.Decode(&a); err != nil {
				_ = resp.Body.Close()
				return err
			}
			if a.ObjectID != "0" {
				if o, ok := oc[a.ObjectID]; ok {
					o.Attribute = append(o.Attribute, &a)
				}
			} else {
				e.Attribute = append(e.Attribute, &a)
			}
		}
		_ = resp.Body.Close()
		// Guess if the next page might still contain objects
		finished = size < w.Options.Buffer
	}
	return nil
}

type respEvent struct {
	Event *event.Event `json:"Event"`
}

type respObject struct {
	Object *object.Object `json:"Object"`
}
