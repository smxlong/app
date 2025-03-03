// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/smxlong/app/users/ent/base"
	"github.com/smxlong/app/users/ent/predicate"
)

// BaseUpdate is the builder for updating Base entities.
type BaseUpdate struct {
	config
	hooks    []Hook
	mutation *BaseMutation
}

// Where appends a list predicates to the BaseUpdate builder.
func (bu *BaseUpdate) Where(ps ...predicate.Base) *BaseUpdate {
	bu.mutation.Where(ps...)
	return bu
}

// SetUpdatedAt sets the "updated_at" field.
func (bu *BaseUpdate) SetUpdatedAt(t time.Time) *BaseUpdate {
	bu.mutation.SetUpdatedAt(t)
	return bu
}

// Mutation returns the BaseMutation object of the builder.
func (bu *BaseUpdate) Mutation() *BaseMutation {
	return bu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (bu *BaseUpdate) Save(ctx context.Context) (int, error) {
	bu.defaults()
	return withHooks(ctx, bu.sqlSave, bu.mutation, bu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (bu *BaseUpdate) SaveX(ctx context.Context) int {
	affected, err := bu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (bu *BaseUpdate) Exec(ctx context.Context) error {
	_, err := bu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (bu *BaseUpdate) ExecX(ctx context.Context) {
	if err := bu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (bu *BaseUpdate) defaults() {
	if _, ok := bu.mutation.UpdatedAt(); !ok {
		v := base.UpdateDefaultUpdatedAt()
		bu.mutation.SetUpdatedAt(v)
	}
}

func (bu *BaseUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(base.Table, base.Columns, sqlgraph.NewFieldSpec(base.FieldID, field.TypeString))
	if ps := bu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := bu.mutation.UpdatedAt(); ok {
		_spec.SetField(base.FieldUpdatedAt, field.TypeTime, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, bu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{base.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	bu.mutation.done = true
	return n, nil
}

// BaseUpdateOne is the builder for updating a single Base entity.
type BaseUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *BaseMutation
}

// SetUpdatedAt sets the "updated_at" field.
func (buo *BaseUpdateOne) SetUpdatedAt(t time.Time) *BaseUpdateOne {
	buo.mutation.SetUpdatedAt(t)
	return buo
}

// Mutation returns the BaseMutation object of the builder.
func (buo *BaseUpdateOne) Mutation() *BaseMutation {
	return buo.mutation
}

// Where appends a list predicates to the BaseUpdate builder.
func (buo *BaseUpdateOne) Where(ps ...predicate.Base) *BaseUpdateOne {
	buo.mutation.Where(ps...)
	return buo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (buo *BaseUpdateOne) Select(field string, fields ...string) *BaseUpdateOne {
	buo.fields = append([]string{field}, fields...)
	return buo
}

// Save executes the query and returns the updated Base entity.
func (buo *BaseUpdateOne) Save(ctx context.Context) (*Base, error) {
	buo.defaults()
	return withHooks(ctx, buo.sqlSave, buo.mutation, buo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (buo *BaseUpdateOne) SaveX(ctx context.Context) *Base {
	node, err := buo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (buo *BaseUpdateOne) Exec(ctx context.Context) error {
	_, err := buo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (buo *BaseUpdateOne) ExecX(ctx context.Context) {
	if err := buo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (buo *BaseUpdateOne) defaults() {
	if _, ok := buo.mutation.UpdatedAt(); !ok {
		v := base.UpdateDefaultUpdatedAt()
		buo.mutation.SetUpdatedAt(v)
	}
}

func (buo *BaseUpdateOne) sqlSave(ctx context.Context) (_node *Base, err error) {
	_spec := sqlgraph.NewUpdateSpec(base.Table, base.Columns, sqlgraph.NewFieldSpec(base.FieldID, field.TypeString))
	id, ok := buo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Base.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := buo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, base.FieldID)
		for _, f := range fields {
			if !base.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != base.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := buo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := buo.mutation.UpdatedAt(); ok {
		_spec.SetField(base.FieldUpdatedAt, field.TypeTime, value)
	}
	_node = &Base{config: buo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, buo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{base.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	buo.mutation.done = true
	return _node, nil
}
