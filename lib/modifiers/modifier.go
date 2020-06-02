package modifiers

import "github.com/0xThiebaut/sigmai/lib/sigma"

type Modifier struct {
	Options *Options
}

type Options struct {
	TagsClear bool
	TagsSet   []string
	TagsRm    []string
	TagsAdd   []string
}

func (m *Modifier) Process(rules []*sigma.Rule) {
	// Ignore if we are empty
	if len(rules) == 0 {
		return
	}
	// Do the additions first
	if len(m.Options.TagsSet) > 0 {
		rules[0].Tags = m.Options.TagsSet
	} else if len(m.Options.TagsAdd) > 0 {
		rules[0].Tags = append(rules[0].Tags, m.Options.TagsAdd...)
	}
	// Then the removals
	if m.Options.TagsClear {
		rules[0].Tags = nil
	} else if len(m.Options.TagsRm) > 0 {
		var excl []string
		for _, tag := range rules[0].Tags {
			ok := true
			for _, rm := range m.Options.TagsRm {
				if tag == rm {
					ok = false
					break
				}
			}
			if ok {
				excl = append(excl, tag)
			}
		}
		rules[0].Tags = excl
	}
}
