package search

import (
	"github.com/0xThiebaut/sigmai/lib/sigma/field"
)

func (s Searches) MarshalYAML() (interface{}, error) {
	if len(s) == 1 {
		return s[0], nil
	}
	return s, nil
}

type Keyword interface{}

type Keywords []Keyword

func (k Keywords) MarshalYAML() (interface{}, error) {
	if len(k) == 1 {
		return k[0], nil
	}
	return k, nil
}

type Search map[field.Field]Keywords

type Searches []Search

type Selections map[string]Searches
