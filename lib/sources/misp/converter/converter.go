package converter

import (
	"fmt"
	"github.com/0xThiebaut/sigmai/lib/sigma"
	"github.com/0xThiebaut/sigmai/lib/sigma/condition"
	"github.com/0xThiebaut/sigmai/lib/sigma/field"
	"github.com/0xThiebaut/sigmai/lib/sigma/search"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/attribute"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/event"
	"github.com/0xThiebaut/sigmai/lib/sources/misp/lib/object"
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

// Convert converts an event.Event into a slice of sigma.Rule.
//
// The first sigma.Rule acts as a global rule containing the core information such as the title and author.
//
// Secondly, the algorithm loops over all standalone attribute.Attribute items part of the event.Event.
// Each attribute.Attribute is converted for each sigma.LogSource to a Mapping (a search.Search and search.Selections).
//
// The search.Selections is a Mapping of attribute parts (e.g. the "Domain" and "IP" for attribute.TypeDomainIP) to the respective search.Searches of which one search.Search is expected to match.
// Concretely, the "Domain" field can be mapped to the search.Searches set of field.CURI, field.CSReferrer and field.RDNS field.Field where one of these search.Search items would suffice the condition.
// A search.Search can contain multiple field.Field mappings all of which need to be matched in order for the search.Search to match the condition.
// One of such example is the for the attribute.TypeIPDstPort where a search.Search requires both a field.DstIP and field.DstPort to match.
//
// From a conditional perspective, the search.Selections items are AND'ed, the search.Searches items are OR'ed and each search.Search is AND'ed as well.
//
// Each attribute.Attribute Mapping can also contain a search.Search when a part of the attribute.Attribute is mapped to only one search.Search;
// Hence not requiring an additional level of abstraction.
//
// As an example, the attribute.TypeFilenameMD5 attribute.Attribute will produce a Mapping where the search.Search matches the field.Hashes and where the Filename will match either of field.Image, field.ParentImage, field.CommandLine, etc...
//
// Thirdly, after having looped the standalone attribute.Attribute, the algorithm loops over the object.Object items within the event.Event.
// Each object.Object's attribute.Attribute is mapped as above with the exception that the logic depends on the attribute.Attribute's attribute.Relation instead of attribute.Type.
// As an example, the object.Process object.Object can distinguish two attribute.TypeFilename where one has the attribute.RelationImage attribute.Relation while the other has the attribute.RelationParentImage attribute.Relation.
func (c *converter) Convert(e *event.Event) []*sigma.Rule {
	// Define a global rule containing all relevant event information
	rule := &sigma.Rule{
		Action:      "global",
		Title:       e.Info,
		Id:          e.UUID,
		Status:      sigma.StatusExperimental,
		Description: fmt.Sprintf("See MISP event %s", e.ID),
		Author:      e.Orgc.Name,
	}
	// Copy the event's tags
	for _, t := range e.Tag {
		if !t.HideTag {
			rule.Tags = append(rule.Tags, t.Name)
		}
	}
	// Map the threat level to the rule
	switch e.ThreatLevelId {
	case event.ThreatLevelHigh:
		rule.Level = sigma.LevelHigh
	case event.ThreatLevelMedium:
		rule.Level = sigma.LevelMedium
	default:
		rule.Level = sigma.LevelLow
	}
	// Define the action document
	rules := []*sigma.Rule{rule}
	// Define the event identifier
	ei := fmt.Sprintf("event%s", e.ID)
	// Define the event scope
	es := make(map[sigma.LogSource]EventScope)
	// Loop the event's attributes
	for _, a := range e.Attribute {
		// Skip deleted attributes
		if a.Deleted {
			continue
		}
		// Computer the attribute identifier
		ai := fmt.Sprintf("%sattr%s", ei, a.ID)
		// Loop the converted log-sources
		for l, m := range c.convertStandalone(a) {
			// Get the log-source's scope
			scope, ok := es[l]
			if !ok {
				scope = EventScope{Search: make(search.Search)}
			}
			if len(m.Selections) > 0 {
				detection := sigma.Detection{Condition: condition.AllOfPattern(fmt.Sprintf("%smapping*", ai)), Searches: make(map[string][]search.Searches)}
				// Loop the searches
				for name, searches := range m.Selections {
					// Define the search identifier
					si := fmt.Sprintf("%smapping%s", ai, name)
					// Append the searches to the scope's detection
					detection.Searches[si] = []search.Searches{searches}
				}

				if len(m.Search) > 0 {
					detection.Condition = condition.From(ai).And(detection.Condition)
					detection.Searches[ai] = []search.Searches{{m.Search}}
				}

				// Loop the mappings
				for name, selection := range m.Selections {
					si := fmt.Sprintf("%smapping%s", ai, name)
					// Get the detection
					detection.Searches[si] = []search.Searches{selection}
				}
				scope.Detections = append(scope.Detections, detection)
			} else if len(m.Search) > 0 {
				for name, word := range m.Search {
					words, _ := scope.Search[name]
					scope.Search[name] = append(words, word)
				}
			}
			es[l] = scope
		}
	}
	// Loop the event's objects
	for _, o := range e.Object {
		// Skip deleted objects
		if o.Deleted {
			continue
		}
		// Compute the object identifier
		oi := fmt.Sprintf("event%sobject%s", e.ID, o.ID)
		// Create detection os
		os := make(map[sigma.LogSource]ObjectScope)
		// Loop the object's attributes
		for _, a := range o.Attribute {
			// Skip deleted attributes
			if a.Deleted {
				continue
			}
			// Compute the attribute identifier
			ai := fmt.Sprintf("%sattr%s", oi, a.ID)
			// Loop the converted log sources
			for ls, m := range c.convertComplex(o, a) {
				// Get the log-source's scope
				scope, ok := os[ls]
				if !ok {
					scope = ObjectScope{Search: make(search.Search), Detection: sigma.Detection{Searches: make(map[string][]search.Searches)}}
				}
				// Apply selections on the scope by appending the searches
				if len(m.Selections) > 0 {
					scope.Detection.Condition = condition.AllOfPattern(fmt.Sprintf("%smapping*", ai)).And(scope.Detection.Condition)
					// Loop the searches
					for name, searches := range m.Selections {
						// Define the search identifier
						si := fmt.Sprintf("%smapping%s", ai, name)
						// Append the searches to the scope's detection
						scope.Detection.Searches[si] = []search.Searches{searches}
					}
				}
				// Apply the search on the scope by merging the keywords per field
				if len(m.Search) > 0 {
					for f, keyword := range m.Search {
						keywords, _ := scope.Search[f]
						scope.Search[f] = append(keywords, keyword)
					}
				}
				// Save the log-source's scope
				os[ls] = scope
			}
		}
		// Loop the os per log-source
		for ls, scope := range os {
			// If there is a search, merge it into the detection
			if len(scope.Search) > 0 {
				scope.Detection.Searches[oi] = []search.Searches{{scope.Search}}
				scope.Detection.Condition = condition.From(oi).And(scope.Detection.Condition)
			}
			// Merge the detection into the detections
			escope, _ := es[ls]
			escope.Detections = append(escope.Detections, scope.Detection)
			es[ls] = escope
		}
	}
	// Convert the detections into per-log-source rules
	for ls, scope := range es {
		// Convert any search into a detection
		if len(scope.Search) > 0 {
			var searches []search.Searches
			for name, words := range scope.Search {
				searches = append(searches, []search.Search{{name: words}})
			}
			scope.Detections = append(scope.Detections, sigma.Detection{
				Searches:  map[string][]search.Searches{ei: searches},
				Condition: condition.From(ei),
			})
		}
		// Define a global rule with the log-source
		rules = append(rules, &sigma.Rule{LogSource: ls, Action: "global"})
		// Follow-up with the detection rules
		for _, detection := range scope.Detections {
			// @TODO: Clean up double-nesting on single keyword fields, even-though the YAML is valid and functional.
			rules = append(rules, &sigma.Rule{Detection: detection})
		}
	}
	// Only return rules if we have at least a selection
	if len(rules) > 1 {
		return rules
	}
	return nil
}

type ObjectScope struct {
	Search    search.Search
	Detection sigma.Detection
}

type EventScope struct {
	Search     search.Search
	Detections []sigma.Detection
}

func (c *converter) convertStandalone(a *attribute.Attribute) map[sigma.LogSource]Mapping {
	switch a.Type {
	case attribute.TypeDomain:
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
	case attribute.TypeEmail, attribute.TypeEmailSrc, attribute.TypeEmailDst, attribute.TypeEmailSubject:
		// @TODO: Create email-based Sigma backends and mapping.
		return nil
	case attribute.TypeFilename:
		return map[sigma.LogSource]Mapping{
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
		m := Mapping{
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
		return map[sigma.LogSource]Mapping{
			{Category: sigma.CategoryProcessCreation, Product: sigma.ProductWindows}: m,
		}
	case attribute.TypeHostname:
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
	case attribute.TypeImphash, attribute.TypeJA3FingerprintMD5, attribute.TypeJarmFingerprint, attribute.TypeMD5, attribute.TypeSHA1, attribute.TypeSHA256, attribute.TypeSHA512, attribute.TypeSSDeep:
		return map[sigma.LogSource]Mapping{
			{Product: sigma.ProductWindows}: {
				Search: search.Search{
					field.Hashes.Contains(): {a.Value},
				},
			},
		}
	case attribute.TypeRegKey:
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
		return map[sigma.LogSource]Mapping{
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
	case attribute.TypeYara, attribute.TypeSnort, attribute.TypeText, attribute.TypeMalwareSample, attribute.TypeVulnerability:
		return nil
	}
	// Log unhandled attribute
	e := c.log.Warn().Str("type", string(a.Type)).Str("attribute", a.ID).Str("event", a.EventId)
	e.Msg("unhandled attribute")
	return nil
}

func (c *converter) convertComplex(o *object.Object, a *attribute.Attribute) map[sigma.LogSource]Mapping {
	// Identify the most credible attribute role
	// Identify the attribute Mapping based on the object name and attribute role
	switch o.Name {
	case object.CommandLine:
		switch a.ObjectRelation {
		case attribute.RelationValue:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.CommandLine.Contains(): {a.Value},
					},
				},
			}
		}
	case object.DomainIP:
		switch a.ObjectRelation {
		case attribute.RelationDomain:
			return map[sigma.LogSource]Mapping{
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
		case attribute.RelationHostname:
			return map[sigma.LogSource]Mapping{
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
		case attribute.RelationIP:
			return map[sigma.LogSource]Mapping{
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
		case attribute.RelationPort:
			return map[sigma.LogSource]Mapping{

				{Category: sigma.CategoryFirewall}: {
					Search: search.Search{
						field.DstPort: {a.Value},
					},
				},
				{Category: sigma.CategoryProxy}: {
					Search: search.Search{
						field.DstPort: {a.Value},
					},
				},
				{Category: sigma.CategoryWebServer}: {
					Search: search.Search{
						field.DstPort: {a.Value},
					},
				},
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.DstPort: {a.Value},
					},
				},
			}
		}
	case object.Email:
		// @TODO: Create email-based Sigma backends and mapping.
		return nil
	case object.File:
		switch a.ObjectRelation {
		case attribute.RelationFileName:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Selections: search.Selections{
						"Filename": {
							{field.Image.EndsWith(): {a.Value}},
							{field.ProcessName.Contains(): {a.Value}},
						},
					},
				},
			}
		case attribute.RelationMD5, attribute.RelationSHA1, attribute.RelationSHA256, attribute.RelationSHA512, attribute.RelationSSDeep, attribute.RelationAuthentihash, attribute.RelationImphash, attribute.RelationVhash:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.Hashes.Contains(): {a.Value},
					},
				},
			}
		case attribute.RelationMalwareSample:
			return nil
		}
	case object.Lnk:
		switch a.ObjectRelation {
		case attribute.RelationMD5, attribute.RelationSHA1, attribute.RelationSHA256, attribute.RelationSHA512, attribute.RelationSSDeep:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.Hashes.Contains(): {a.Value},
					},
				},
			}
		}
	case object.Pe:
		switch a.ObjectRelation {
		case attribute.RelationOriginalFileName, attribute.RelationInternalFileName:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Selections: search.Selections{
						"Filename": {
							{field.Image.EndsWith(): {a.Value}},
							{field.ProcessName.Contains(): {a.Value}},
						},
					},
				},
			}
		case attribute.RelationImphash, attribute.RelationImpfuzzy:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.Hashes.Contains(): {a.Value},
					},
				},
			}
		}
	case object.PeSection, object.ElfSection:
		switch a.ObjectRelation {
		case attribute.RelationMD5, attribute.RelationSHA1, attribute.RelationSHA256, attribute.RelationSHA512, attribute.RelationSSDeep:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.Hashes.Contains(): {a.Value},
					},
				},
			}
		}
	case object.Phishing:
		switch a.ObjectRelation {
		case attribute.RelationUrl, attribute.RelationUrlRedirect:
			return map[sigma.LogSource]Mapping{
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
		}
	case object.Process:
		switch a.ObjectRelation {
		case attribute.RelationImage:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.Image.EndsWith(): {a.Value},
					},
				},
			}
		case attribute.RelationName:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.ProcessName: {a.Value},
					},
				},
			}
		case attribute.RelationParentImage:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.ParentImage.EndsWith(): {a.Value},
					},
				},
			}
		case attribute.RelationCommandLine:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.CommandLine.Contains(): {a.Value},
					},
				},
			}
		case attribute.RelationParentProcessName:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Search: search.Search{
						field.ParentProcessName: {a.Value},
					},
				},
			}
		}
	case object.RegistryKey:
		switch a.ObjectRelation {
		case attribute.RelationKey:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Selections: search.Selections{
						"RegKeyValue": {
							{
								field.TargetObject.EndsWith(): {a.Value},
							},
						},
					},
				},
			}
		}
	case object.Script:
		switch a.ObjectRelation {
		case attribute.RelationFileName:
			return map[sigma.LogSource]Mapping{
				{Product: sigma.ProductWindows}: {
					Selections: search.Selections{
						"Filename": {
							{field.Image.EndsWith(): {a.Value}},
							{field.ProcessName.Contains(): {a.Value}},
						},
					},
				},
			}
		}
	case object.ShortenedLink:
		switch a.ObjectRelation {
		case attribute.RelationShortenedUrl, attribute.RelationRedirectUrl:
			return map[sigma.LogSource]Mapping{
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
		}
	case object.HttpRequest:
		switch a.ObjectRelation {
		case attribute.RelationUri, attribute.RelationUrl:
			return map[sigma.LogSource]Mapping{
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
		case attribute.RelationMethod:
			return map[sigma.LogSource]Mapping{
				sigma.LogSource{Category: sigma.CategoryProxy}: {
					Search: map[field.Field]search.Keywords{
						field.CSMethod: {a.Value},
					},
				},
				sigma.LogSource{Category: sigma.CategoryWebServer}: {
					Search: map[field.Field]search.Keywords{
						field.CSMethod: {a.Value},
					},
				},
			}
		}
	case object.Url, object.DomainCrawled, object.Image:
		switch a.ObjectRelation {
		case attribute.RelationUrl:
			return map[sigma.LogSource]Mapping{
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
		}
	case object.Yara, object.Suricata:
		return nil
	}
	// Log unhandled object and attribute combination
	e := c.log.Warn().Str("relation", string(a.ObjectRelation)).Str("attribute", a.ID).Str("event", a.EventId).Str("object", o.ID).Str("category", o.Name)
	e.Msg("unhandled object relation")
	return nil
}

// Mapping represents the different possible field.Field mappings.
type Mapping struct {
	// A search is propagated to the parent
	Search search.Search
	// Selections are kept as independent but the condition is then propagated to the parent
	Selections search.Selections
}
