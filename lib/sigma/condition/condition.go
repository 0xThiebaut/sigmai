package condition

import "gopkg.in/yaml.v2"

type Aggregator string

const (
	AggregatorCount Aggregator = "count"
	AggregatorMin   Aggregator = "min"
	AggregatorMax   Aggregator = "max"
	AggregatorAvg   Aggregator = "avg"
	AggregatorSum   Aggregator = "sum"
)

type Operator string

const (
	OperatorLargerThan       Operator = ">"
	OperatorSmallerThan      Operator = "<"
	OperatorLargerOrEqualTo  Operator = ">="
	OperatorSmallerOrEqualTo Operator = "<="
	OperatorEqualTo          Operator = "="
)

type Condition interface {
	Or(cond Condition) Condition
	And(cond Condition) Condition
	yaml.Marshaler
	String() string
}

type singleCondition string

func (c singleCondition) String() string {
	return string(c)
}

func (c singleCondition) MarshalYAML() (interface{}, error) {
	return c.String(), nil
}

func (c singleCondition) And(cond Condition) Condition {
	return And(c, cond)
}

func (c singleCondition) Or(cond Condition) Condition {
	return Or(c, cond)
}

func From(identifier string) Condition {
	return singleCondition(identifier)
}

func AllOfPattern(pattern string) Condition {
	return singleCondition("all of " + pattern)
}

func OneOfThem() Condition {
	return singleCondition("one of them")
}
