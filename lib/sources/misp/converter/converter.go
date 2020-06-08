package converter

import (
	"fmt"
	"github.com/0xThiebaut/sigmai/lib/sigma"
	"github.com/0xThiebaut/sigmai/lib/sigma/condition"
	"github.com/0xThiebaut/sigmai/lib/sigma/field"
	"github.com/0xThiebaut/sigmai/lib/sigma/search"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/attribute"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/event"
	"github.com/rs/zerolog"
	"strings"
)

type Converter interface {
	Convert(e *event.Event) []*sigma.Rule
}

type converter struct {
	log zerolog.Logger
}

func New(l zerolog.Logger) Converter {
	return &converter{log: l}
}

// Does some black-magic.
// I can't explain it any more but it does the job...
func (c *converter) Convert(e *event.Event) []*sigma.Rule {
	rule := &sigma.Rule{
		Action:      "global",
		Title:       e.Info,
		Id:          e.UUID,
		Status:      sigma.StatusExperimental,
		Description: fmt.Sprintf("See MISP event %s", e.ID),
		Author:      e.Orgc.Name,
	}
	for _, t := range e.Tag {
		if !t.HideTag {
			rule.Tags = append(rule.Tags, t.Name)
		}
	}
	// Define the severity
	switch e.ThreatLevelId {
	case event.ThreatLevelHigh:
		rule.Level = sigma.LevelHigh
	case event.ThreatLevelMedium:
		rule.Level = sigma.LevelMedium
	default:
		rule.Level = sigma.LevelLow
	}
	// Define action document
	rules := []*sigma.Rule{rule}

	// For each logsource
	lselections := map[sigma.LogSource]search.Selections{}
	lcondion := map[sigma.LogSource]condition.Condition{}
	// Define the event identifier
	ei := fmt.Sprintf("event%s", e.ID)
	for _, a := range e.Attribute {
		// Define the attribute identifier
		ai := fmt.Sprintf("%sattr%s", ei, a.ID)
		// Loop the mapped log-sources
		for l, m := range c.convert(a) {
			// Check if it is a multi search
			simple := len(m.Search) > 0
			multi := len(m.Selections) > 0
			// Get or create a set of selections for the current log-source
			selections, ok := lselections[l]
			if !ok {
				selections = search.Selections{}
			}
			// Check if we have a search to propagate
			if simple {
				// If it is a complex search, use the attribute identifier
				// Otherwise, use the event identifier
				si := ei
				if multi {
					si = ai
				}
				// Get or create the parent searches
				ss, ok := selections[si]
				if !ok || len(ss) == 0 {
					ss = search.Searches{{}}
					// Append or create the condition
					acond := condition.From(si)
					if multi {
						acond = acond.And(condition.AllOfPattern(fmt.Sprintf("%smapping*", si)))
					}
					if cond, ok := lcondion[l]; ok {
						lcondion[l] = cond.Or(acond)
					} else {
						lcondion[l] = acond
					}
				}
				// Loop, shouldn't do more than 1
				for _, s := range ss {
					// Loop the fields to merge the keywords
					for f, mkeywords := range m.Search {
						// Get or create the keywords
						ekeywords, ok := s[f]
						if !ok {
							ekeywords = search.Keywords{}
						}
						// Merge the keywords
						ekeywords = append(ekeywords, mkeywords...)
						// Save the merged keywords
						s[f] = ekeywords
					}
				}
				// Save the selection
				selections[si] = ss
			}
			// Check if we have selections to propagate
			if multi {
				for si, ss := range m.Selections {
					si := fmt.Sprintf("%smapping%s", ai, si)
					selections[si] = ss
				}
				// Check if a condition was already build
				if !simple {
					// Append or create the condition
					acond := condition.AllOfPattern(fmt.Sprintf("%smapping*", ai))
					if cond, ok := lcondion[l]; ok {
						lcondion[l] = cond.Or(acond)
					} else {
						lcondion[l] = acond
					}
				}
			}

			// Save the selections
			lselections[l] = selections
		}
	}
	for _, o := range e.Object {
		ocondition := map[sigma.LogSource]condition.Condition{}
		oi := fmt.Sprintf("event%sobject%s", e.ID, o.ID)
		for _, a := range o.Attribute {
			// Define the attribute identifier
			ai := fmt.Sprintf("%sattr%s", oi, a.ID)
			// Loop the mapped log-sources
			for l, m := range c.convert(a) {
				// Check if it is a multi search
				simple := len(m.Search) > 0
				multi := len(m.Selections) > 0
				// Get or create a set of selections for the current log-source
				selections, ok := lselections[l]
				if !ok {
					selections = search.Selections{}
				}
				// Check if we have a search to propagate
				if simple {
					// If it is a complex search, use the attribute identifier
					// Otherwise, use the event identifier
					si := oi
					if multi {
						si = ai
					}
					// Get or create the parent searches
					ss, ok := selections[si]
					if !ok || len(ss) == 0 {
						ss = search.Searches{{}}
						// Append or create the condition
						acond := condition.From(si)
						if multi {
							acond = acond.And(condition.AllOfPattern(fmt.Sprintf("%smapping*", si)))
						}
						if cond, ok := ocondition[l]; ok {
							ocondition[l] = cond.And(acond)
						} else {

							ocondition[l] = acond
						}
					}
					// Loop, shouldn't do more than 1
					for _, s := range ss {
						// Loop the fields to merge the keywords
						for f, mkeywords := range m.Search {
							// Get or create the keywords
							ekeywords, ok := s[f]
							if !ok {
								ekeywords = search.Keywords{}
							}
							// Merge the keywords
							ekeywords = append(ekeywords, mkeywords...)
							// Save the merged keywords
							s[f] = ekeywords
						}
					}
					// Save the selection
					selections[si] = ss
				}
				// Check if we have selections to propagate
				if multi {
					for si, ss := range m.Selections {
						si := fmt.Sprintf("%smapping%s", ai, si)
						selections[si] = ss
					}
					// Check if a condition was already build
					if !simple {
						// Append or create the condition
						acond := condition.AllOfPattern(fmt.Sprintf("%smapping*", ai))
						if cond, ok := ocondition[l]; ok {
							ocondition[l] = cond.And(acond)
						} else {
							ocondition[l] = acond
						}
					}
				}
				// Save the selections
				lselections[l] = selections
			}
		}
		// Merge the conditions into logsoruce's ones
		for l, ocond := range ocondition {
			if cond, ok := lcondion[l]; ok {
				lcondion[l] = cond.Or(ocond)
			} else {
				lcondion[l] = ocond
			}
		}
	}
	// Explode event-level attributes (i.e. hashes will rarely match alongside IPs)
	for _, lselect := range lselections {
		if s, ok := lselect[ei]; ok && len(s) == 1 {
			// Create an array of exploded searches
			exps := search.Searches{}
			// For each event level field
			for f, k := range s[0] {
				// Create a earch explicitly for that field
				exps = append(exps, search.Search{
					f: k,
				})
			}
			// Override the event level search
			lselect[ei] = exps
		}
	}
	// Create rules per LogSource
	for l, s := range lselections {
		c, ok := lcondion[l]
		if !ok {
			c = condition.OneOfThem()
		}
		rules = append(rules, &sigma.Rule{
			LogSource: l,
			Detection: sigma.Detection{
				Condition: c,
				Searches:  s,
			},
		})
	}
	// Only return rules if we have at least a selection
	if len(lselections) > 0 {
		return rules
	}
	return nil
}

func (c *converter) convert(a *attribute.Attribute) map[sigma.LogSource]mapping {
	switch a.Type {
	case attribute.TypeDomain:
		return map[sigma.LogSource]mapping{
			sigma.LogSource{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"Domain": {
						{field.CURI.Contains(): {a.Value}},
						{field.CSReferrer.Contains(): {a.Value}},
						{field.RDNS.Contains(): {a.Value}},
					},
				},
			},
			sigma.LogSource{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"Domain": {
						{field.CURI.Contains(): {a.Value}},
						{field.CSReferrer.Contains(): {a.Value}},
						{field.RDNS.Contains(): {a.Value}},
					},
				},
			},
		}
	case attribute.TypeDomainIP:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Join all the first parts as the filename
		domain := strings.Join(parts[:len(parts)-1], "|")
		// Keep the last part as the hash, which won't contain the "|" character
		ip := parts[len(parts)-1]
		return map[sigma.LogSource]mapping{
			sigma.LogSource{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"Domain": {
						{field.CURI.Contains(): {domain}},
						{field.CSReferrer.Contains(): {domain}},
						{field.RDNS.Contains(): {domain}},
					},
					"IP": {
						{field.SrcIP: {ip}},
						{field.DstIP: {ip}},
						{field.SourceIP: {ip}},
						{field.DestinationIP: {ip}},
					},
				},
			},
			sigma.LogSource{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"Domain": {
						{field.CURI.Contains(): {domain}},
						{field.CSReferrer.Contains(): {domain}},
						{field.RDNS.Contains(): {domain}},
					},
					"IP": {
						{field.SrcIP: {ip}},
						{field.DstIP: {ip}},
						{field.SourceIP: {ip}},
						{field.DestinationIP: {ip}},
					},
				},
			},
		}
	case attribute.TypeFilename:
		return map[sigma.LogSource]mapping{
			{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"Filename": {
						{field.Image.EndsWith(): {a.Value}},
						{field.ParentImage.EndsWith(): {a.Value}},
						{field.CommandLine.Contains(): {a.Value}},
						{field.ParentCommandLine.Contains(): {a.Value}},
						{field.ProcessName: {a.Value}},
						{field.ParentProcessName: {a.Value}},
					},
				},
			},
		}
	case attribute.TypeFilenameImphash, attribute.TypeFilenameMD5, attribute.TypeFilenameSHA1, attribute.TypeFilenameSHA256, attribute.TypeFilenameSHA384, attribute.TypeFilenameSHA512, attribute.TypeFilenameSSDeep:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Join all the first parts as the filename
		filename := strings.Join(parts[:len(parts)-1], "|")
		// Keep the last part as the hash, which won't contain the "|" character
		hash := parts[len(parts)-1]
		// Define a shared mapping
		m := mapping{
			// Propagate the hash to the parent's search
			Search: search.Search{field.Hashes.Contains(): {hash}},
			// Add a new selection to search for the filename, identified by the search identifier
			Selections: search.Selections{
				"Filename": {
					{field.Image.EndsWith(): {filename}},
					{field.ParentImage.Contains(): {filename}},
					{field.CommandLine.Contains(): {filename}},
					{field.ParentCommandLine.Contains(): {filename}},
					{field.ProcessName.Contains(): {filename}},
					{field.ParentProcessName.Contains(): {filename}},
				},
			},
		}
		// Associate the mapping to any log-source of interest.
		return map[sigma.LogSource]mapping{
			{Category: sigma.CategoryProcessCreation, Product: sigma.ProductWindows}: m,
		}
	case attribute.TypeHostname:
		return map[sigma.LogSource]mapping{
			sigma.LogSource{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"Hostname": {
						{field.CURI.Contains(): {a.Value}},
						{field.CSReferrer.Contains(): {a.Value}},
						{field.RDNS.Contains(): {a.Value}},
						{field.CSHost.Contains(): {a.Value}},
					},
				},
			},
			sigma.LogSource{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"Hostname": {
						{field.CURI.Contains(): {a.Value}},
						{field.CSReferrer.Contains(): {a.Value}},
						{field.RDNS.Contains(): {a.Value}},
						{field.CSHost.Contains(): {a.Value}},
					},
				},
			},
			sigma.LogSource{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"Hostname": {
						{field.DestinationHostname: {a.Value}},
						{field.SourceHostname: {a.Value}},
						{field.Computer: {a.Value}},
						{field.ComputerName: {a.Value}},
						{field.Workstation: {a.Value}},
						{field.WorkstationName: {a.Value}},
					},
				},
			},
		}
	case attribute.TypeHostnamePort:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Turn hostname|port into hostname and hostname:port
		h := strings.Join(parts[:len(parts)-1], "|")
		// Associate the mapping to any log-source of interest.
		return map[sigma.LogSource]mapping{
			sigma.LogSource{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"Hostname": {
						{field.CURI.Contains(): {h}},
						{field.CSReferrer.Contains(): {h}},
						{field.RDNS.Contains(): {h}},
						{field.CSHost.Contains(): {h}},
					},
				},
			},
			sigma.LogSource{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"Hostname": {
						{field.CURI.Contains(): {h}},
						{field.CSReferrer.Contains(): {h}},
						{field.RDNS.Contains(): {h}},
						{field.CSHost.Contains(): {h}},
					},
				},
			},
			sigma.LogSource{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"Hostname": {
						{field.DestinationHostname: {h}},
						{field.SourceHostname: {h}},
						{field.Computer: {h}},
						{field.ComputerName: {h}},
						{field.Workstation: {h}},
						{field.WorkstationName: {h}},
					},
				},
			},
		}
	case attribute.TypeIPDst:
		return map[sigma.LogSource]mapping{
			{Category: sigma.CategoryFirewall}: {
				Search: search.Search{
					field.DstIP: {a.Value},
				},
			},
			{Category: sigma.CategoryProxy}: {
				Search: search.Search{
					field.DstIP: {a.Value},
				},
			},
			{Category: sigma.CategoryWebServer}: {
				Search: search.Search{
					field.DstIP: {a.Value},
				},
			},
			{Product: sigma.ProductWindows}: {
				Search: search.Search{
					field.DestinationIP: {a.Value},
				},
			},
		}
	case attribute.TypeIPDstPort:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Join all the first parts as the filename
		ip := strings.Join(parts[:len(parts)-1], "|")
		// Keep the last part as the hash, which won't contain the "|" character
		port := parts[len(parts)-1]
		// Associate the mapping to any log-source of interest.
		return map[sigma.LogSource]mapping{
			{Category: sigma.CategoryFirewall}: {
				Selections: search.Selections{
					"IPDstPort": {
						{
							field.DstIP:   {ip},
							field.DstPort: {port},
						},
					},
				},
			},
			{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"IPDstPort": {
						{
							field.DstIP:   {ip},
							field.DstPort: {port},
						},
					},
				},
			},
			{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"IPDstPort": {
						{
							field.DstIP:   {ip},
							field.DstPort: {port},
						},
					},
				},
			},
			{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"IPDstPort": {
						{
							field.DestinationIP:   {ip},
							field.DestinationPort: {port},
						},
					},
				},
			},
		}
	case attribute.TypeIPSrc:
		return map[sigma.LogSource]mapping{
			{Category: sigma.CategoryFirewall}: {
				Search: search.Search{
					field.SrcIP: {a.Value},
				},
			},
			{Category: sigma.CategoryProxy}: {
				Search: search.Search{
					field.SrcIP: {a.Value},
				},
			},
			{Category: sigma.CategoryWebServer}: {
				Search: search.Search{
					field.SrcIP: {a.Value},
				},
			},
			{Product: sigma.ProductWindows}: {
				Search: search.Search{
					field.SourceIP: {a.Value},
				},
			},
		}
	case attribute.TypeIPSrcPort:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Join all the first parts as the filename
		ip := strings.Join(parts[:len(parts)-1], "|")
		// Keep the last part as the hash, which won't contain the "|" character
		port := parts[len(parts)-1]
		// Associate the mapping to any log-source of interest.
		return map[sigma.LogSource]mapping{
			{Category: sigma.CategoryFirewall}: {
				Selections: search.Selections{
					"IPSrcPort": {
						{
							field.SrcIP:   {ip},
							field.SrcPort: {port},
						},
					},
				},
			},
			{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"IPSrcPort": {
						{
							field.SrcIP:   {ip},
							field.SrcPort: {port},
						},
					},
				},
			},
			{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"IPSrcPort": {
						{
							field.SrcIP:   {ip},
							field.SrcPort: {port},
						},
					},
				},
			},
			{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"IPSrcPort": {
						{
							field.SourceIP:   {ip},
							field.SourcePort: {port},
						},
					},
				},
			},
		}
	case attribute.TypeImphash, attribute.TypeMD5, attribute.TypeSHA1, attribute.TypeSHA256, attribute.TypeSHA512, attribute.TypeSSDeep:
		return map[sigma.LogSource]mapping{
			{Product: sigma.ProductWindows}: {
				Search: search.Search{
					field.Hashes.Contains(): {a.Value},
				},
			},
		}
	case attribute.TypeRegKey:
		return map[sigma.LogSource]mapping{
			{Product: sigma.ProductWindows}: {
				Search: search.Search{
					field.TargetObject: {a.Value},
				},
			},
		}
	case attribute.TypeRegKeyValue:
		// Explode the composed attribute
		parts := strings.Split(a.Value, "|")
		// Join all the first parts as the filename
		rekey := parts[0]
		// Keep the last part as the hash, which won't contain the "|" character
		value := strings.Join(parts[1:], "|")
		// Associate the mapping to any log-source of interest.
		return map[sigma.LogSource]mapping{
			{Product: sigma.ProductWindows}: {
				Selections: search.Selections{
					"RegKeyValue": {
						{
							field.TargetObject: {rekey},
							field.Description:  {value},
						},
					},
				},
			},
		}
	case attribute.TypeURI, attribute.TypeURL:
		return map[sigma.LogSource]mapping{
			sigma.LogSource{Category: sigma.CategoryProxy}: {
				Selections: search.Selections{
					"URI": {
						{field.CURI: {a.Value}},
						{field.CSReferrer: {a.Value}},
						{field.RDNS: {a.Value}},
					},
				},
			},
			sigma.LogSource{Category: sigma.CategoryWebServer}: {
				Selections: search.Selections{
					"URI": {
						{field.CURI: {a.Value}},
						{field.CSReferrer: {a.Value}},
						{field.RDNS: {a.Value}},
					},
				},
			},
		}
	default:
		e := c.log.Warn().Str("type", string(a.Type)).Str("attribute", a.ID).Str("event", a.EventId)
		if len(a.ObjectID) > 0 {
			e = e.Str("object", a.ObjectID)
		}
		e.Msg("unhandled type")
	}
	return nil
}

// Represents the different possible mappings
type mapping struct {
	// A search is propagated to the parent
	Search search.Search
	// Searches are kept as independent but the condition is then propagated to the parent
	Selections search.Selections
}
