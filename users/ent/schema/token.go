package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Token holds the schema definition for the Token entity.
type Token struct {
	ent.Schema
}

// Fields of the Token.
func (Token) Fields() []ent.Field {
	return []ent.Field{
		field.String("token").
			NotEmpty().
			Unique(),
		field.Enum("type").
			Values("reset_password").
			Default("reset_password"),
		field.Time("expires_at"),
	}
}

// Edges of the Token.
func (Token) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("tokens").
			Unique(),
	}
}

// Mixin of the Token.
func (Token) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Base{},
	}
}
