package condition

import "strings"

func Or(a Condition, b Condition) Condition {
	if oc, ok := a.(*orCondition); ok {
		return oc.And(b)
	} else if oc, ok = b.(*orCondition); ok {
		return oc.And(a)
	}
	return &orCondition{or: []Condition{a, b}}
}

type orCondition struct {
	or []Condition
}

func (c *orCondition) Or(cond Condition) Condition {
	if oc, ok := cond.(*orCondition); ok {
		c.or = append(c.or, oc.or...)
	} else {
		c.or = append(c.or, cond)
	}
	return c
}

func (c *orCondition) And(cond Condition) Condition {
	return And(c, cond)
}

func (c *orCondition) MarshalYAML() (interface{}, error) {
	return c.or, nil
}

func (c *orCondition) String() string {
	x := len(c.or)
	if x == 1 {
		return c.or[0].String()
	}
	s := make([]string, len(c.or))
	for i, cond := range c.or {
		if sc, ok := cond.(singleCondition); ok {
			s[i] = sc.String()
		} else {
			s[i] = "(" + cond.String() + ")"
		}
	}
	return strings.Join(s, " or ")
}
