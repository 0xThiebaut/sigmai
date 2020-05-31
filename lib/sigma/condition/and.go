package condition

import (
	"strings"
)

func And(a Condition, b Condition) Condition {
	if ac, ok := a.(*andCondition); ok {
		return ac.And(b)
	} else if ac, ok = b.(*andCondition); ok {
		return ac.And(a)
	}
	return &andCondition{and: []Condition{a, b}}
}

type andCondition struct {
	and []Condition
}

func (c *andCondition) And(cond Condition) Condition {
	if ac, ok := cond.(*andCondition); ok {
		c.and = append(c.and, ac.and...)
	} else {
		c.and = append(c.and, cond)
	}
	return c
}

func (c *andCondition) Or(cond Condition) Condition {
	return Or(c, cond)
}

func (c *andCondition) MarshalYAML() (interface{}, error) {
	return c.String(), nil
}

func (c *andCondition) String() string {
	x := len(c.and)
	if x == 1 {
		return c.and[0].String()
	}
	s := make([]string, len(c.and))
	for i, cond := range c.and {
		if sc, ok := cond.(singleCondition); ok {
			s[i] = sc.String()
		} else {
			s[i] = "(" + cond.String() + ")"
		}
	}
	return strings.Join(s, " and ")
}
