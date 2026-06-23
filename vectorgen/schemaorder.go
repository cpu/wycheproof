package vectorgen

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/c2sp/wycheproof"
)

// topLevelProperties returns the top-level properties of schemaName in
// declaration order. Used to position fields when synthesizing a new vector
// file.
func topLevelProperties(schemasFS fs.FS, schemaName string) ([]string, error) {
	root, err := loadSchema(schemasFS, schemaName)
	if err != nil {
		return nil, err
	}
	return propertyNames(root)
}

// testVectorProperties returns the test-vector object's properties in
// declaration order, by walking the schema from the top-level down through
// testGroups.items -> tests.items, following local $refs.
//
// The returned slice is the canonical order vectorgen.Update uses to position
// newly added keys.
//
// Schemas in this repo always shape the test-vector definition as either an
// inline object or a $ref into the same document's #/definitions block; cross-
// document refs and remote refs are not supported.
func testVectorProperties(schemasFS fs.FS, schemaName string) ([]string, error) {
	root, err := loadSchema(schemasFS, schemaName)
	if err != nil {
		return nil, err
	}

	testGroupItems, err := navigate(root, root, "properties", "testGroups", "items")
	if err != nil {
		return nil, fmt.Errorf("locating testGroups.items: %w", err)
	}

	testItems, err := navigate(root, testGroupItems, "properties", "tests", "items")
	if err != nil {
		return nil, fmt.Errorf("locating tests.items: %w", err)
	}

	return propertyNames(testItems)
}

// loadSchema reads and parses schemaName from schemasFS (or the embedded FS
// when schemasFS is nil), returning the schema's root object.
func loadSchema(schemasFS fs.FS, schemaName string) (RawObject, error) {
	if schemasFS == nil {
		schemasFS = wycheproof.Schemas
	}
	data, err := fs.ReadFile(schemasFS, schemaName)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	root, err := parseObject(data)
	if err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	return root, nil
}

// propertyNames returns the keys of obj's "properties" object in declaration
// order.
func propertyNames(obj RawObject) ([]string, error) {
	propsVal, ok := obj.Get("properties")
	if !ok {
		return nil, errors.New("schema object has no properties")
	}
	props, err := parseObject(propsVal)
	if err != nil {
		return nil, fmt.Errorf("parsing properties: %w", err)
	}
	names := make([]string, len(props))
	for i := range props {
		names[i] = props[i].Name
	}
	return names, nil
}

// navigate walks obj following path, resolving any $ref it encounters in the
// same document (root). $refs to other documents are not supported.
func navigate(root, obj RawObject, path ...string) (RawObject, error) {
	cur := obj
	for _, step := range path {
		resolved, err := resolveRef(root, cur)
		if err != nil {
			return nil, err
		}
		cur = resolved

		next, ok := cur.Get(step)
		if !ok {
			return nil, fmt.Errorf("path step %q not found", step)
		}

		cur, err = parseObject(next)
		if err != nil {
			return nil, fmt.Errorf("step %q: %w", step, err)
		}
	}

	return resolveRef(root, cur)
}

// resolveRef checks obj for a $ref field; if present and pointing into the
// same document, returns the referenced object. Otherwise returns obj.
func resolveRef(root, obj RawObject) (RawObject, error) {
	refVal, ok := obj.Get("$ref")
	if !ok {
		return obj, nil
	}

	var ref string
	if err := json.Unmarshal(refVal, &ref); err != nil {
		return nil, fmt.Errorf("decoding $ref: %w", err)
	}

	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("only same-document $refs are supported, got %q", ref)
	}

	cur := root
	for _, step := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		v, ok := cur.Get(step)
		if !ok {
			return nil, fmt.Errorf("$ref %q: step %q not found", ref, step)
		}

		next, err := parseObject(v)
		if err != nil {
			return nil, fmt.Errorf("$ref %q step %q: %w", ref, step, err)
		}

		cur = next
	}

	return cur, nil
}
