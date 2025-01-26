package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Base mixin
type Base struct {
	ent.Schema
}

// Fields of the Base.
func (Base) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique().
			Immutable().
			MinLen(36).
			MaxLen(36).
			DefaultFunc(func() string {
				return uuid.New().String()
			}),
		field.Time("created_at").
			Immutable().
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
