package workers

import (
	"errors"
	"net/http"
)

type Options struct {
	URL              string
	Key              string
	Insecure         bool
	Period           []string
	Events           []int
	IDSIgnore        bool
	IDSExclude       bool
	PublishedInclude bool
	PublishedExclude bool
	Buffer           int
	WarningInclude   bool
	Tags             []string
	ThreatLevel      []string
	Keywords         []string
}

func (o Options) Validate() error {
	if len(o.URL) == 0 {
		return errors.New("missing MISP URL")
	}
	if len(o.Key) == 0 {
		return errors.New("missing MISP Authorization Key")
	}
	if o.Buffer <= 0 {
		return errors.New("buffer must at least be one")
	}
	return nil
}

func (o Options) Authorize(req *http.Request) {
	req.Header.Add("Authorization", o.Key)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
}

func (o Options) EventFilter() map[string]interface{} {
	f := map[string]interface{}{
		"limit":    o.Buffer,
		"metadata": "1",
	}
	if len(o.Events) > 0 {
		f["eventid"] = o.Events
	}
	if o.PublishedInclude != o.PublishedExclude {
		if o.PublishedInclude {
			f["published"] = "1"
		} else {
			f["published"] = "0"
		}
	}
	if len(o.Tags) > 0 {
		f["tags"] = o.Tags
	}
	if len(o.Period) > 0 {
		f["date"] = o.Period
	}
	if len(o.ThreatLevel) > 0 {
		f["threat_level_id"] = o.ThreatLevel
	}
	if len(o.Keywords) > 0 {
		substrings := make([]string, len(o.Keywords))
		for i, k := range o.Keywords {
			substrings[i] = "%" + k + "%"
		}
		f["eventinfo"] = substrings
	}
	return f
}

func (o Options) ObjectFilter() map[string]interface{} {
	f := map[string]interface{}{
		"limit":    o.Buffer,
		"metadata": "1",
	}
	return f
}

func (o Options) AttributeFilter() map[string]interface{} {
	f := map[string]interface{}{
		"limit": o.Buffer,
	}
	if !o.IDSIgnore {
		if o.IDSExclude {
			f["to_ids"] = "0"
		} else {
			f["to_ids"] = "1"
		}
	}
	if !o.WarningInclude {
		f["enforceWarninglist"] = "1"
	}
	return f
}
