package condition

import (
	"strings"
)

func And(a Condition, b Condition) Condition {
	return (&andCondition{}).And(a).And(b)
}

type andCondition struct {
	and []Condition
}

func (c *andCondition) And(cond Condition) Condition {
	if ac, ok := cond.(*andCondition); ok && ac != nil {
		c.and = append(c.and, ac.and...)
	} else if cond != nil {
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
	switch len(c.and) {
	case 0:
		return ""
	case 1:
		return c.and[0].String()
	default:
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
}
