package sigma

type Relationship struct {
	Id   string
	Type Relation
}

type Relation string

const (
	RelationDerived   Relation = "derived"
	RelationObsoletes Relation = "obsoletes"
	RelationMerged    Relation = "merged"
	RelationRenamed   Relation = "renamed"
)
