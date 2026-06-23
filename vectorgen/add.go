package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Add applies env to the vector file at vectorPath. If the file does not
// exist, it is created from env's top-level fields. If it exists, the
// behavior depends on env.IntoGroup: when set, tests are appended into the
// matching existing group; otherwise a new group is appended.
//
// The result is schema-validated before writing. On validation failure the
// merged content is written to vectorPath+".rej" and the original is left
// untouched.
func Add(vectorPath string, env AddEnvelope, opts Options) error {
	if len(env.Tests) == 0 {
		return errors.New("envelope tests are empty")
	}

	existing, err := os.ReadFile(vectorPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return addNewFile(vectorPath, env, opts)
	case err != nil:
		return err
	}

	root, err := parseObject(existing)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", vectorPath, err)
	}

	if env.IntoGroup != "" {
		root, err = appendIntoGroup(root, env.IntoGroup, env.Tests)
	} else {
		if len(env.GroupTemplate) == 0 {
			return errors.New("envelope is missing groupTemplate (and intoGroup is not set)")
		}
		root, err = appendNewGroup(root, env.GroupTemplate, env.Tests)
	}
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// AddEnvelope describes a single vectorgen add operation's input.
type AddEnvelope struct {
	// File-level fields used only when creating a new vector file. Ignored
	// when appending to an existing file.
	Algorithm string   `json:"algorithm,omitempty"`
	Schema    string   `json:"schema,omitempty"`
	Header    []string `json:"header,omitempty"`

	// GroupTemplate is the new test group's object minus its tests array.
	// Required for append-group mode. Ignored when IntoGroup is set.
	GroupTemplate jsontext.Value `json:"groupTemplate,omitempty"`

	// Tests are the new test objects to add. tcId in each is ignored; the
	// tool assigns them.
	Tests []jsontext.Value `json:"tests"`

	// Notes to merge into the file's top-level notes. Conflicting entries
	// (same key, different content) are rejected.
	Notes RawObject `json:"notes,omitempty"`

	// IntoGroup, if non-empty, appends Tests into an existing group with the
	// given source name (and optional version, separated by "@"). When set,
	// GroupTemplate is ignored.
	//
	// This field is not deserialized from the envelope; it is set by callers
	// (typically the CLI's --into-group flag).
	IntoGroup string `json:"-"`
}

// addNewFile is Add's helper for initializing a brand-new file.
//
// The target does not exist, we synthesize a new file from env using
// schema-required field ordering at the top level.
func addNewFile(vectorPath string, env AddEnvelope, opts Options) error {
	if env.Algorithm == "" {
		return errors.New("creating a new file requires envelope.algorithm")
	}
	if env.Schema == "" {
		return errors.New("creating a new file requires envelope.schema")
	}
	if len(env.GroupTemplate) == 0 {
		return errors.New("creating a new file requires envelope.groupTemplate")
	}

	schemaOrder, err := topLevelProperties(opts.SchemasFS, env.Schema)
	if err != nil {
		return fmt.Errorf("reading schema %s: %w", env.Schema, err)
	}

	values := map[string]jsontext.Value{
		"algorithm":     mustMarshal(env.Algorithm),
		"schema":        mustMarshal(env.Schema),
		"numberOfTests": jsontext.Value("0"),
		"notes":         emptyObject(),
		"testGroups":    jsontext.Value("[]"),
	}
	if len(env.Header) > 0 {
		values["header"] = mustMarshal(env.Header)
	}

	root := assembleTopLevel(values, schemaOrder)

	root, err = appendNewGroup(root, env.GroupTemplate, env.Tests)
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// appendNewGroup appends a fresh group to root.testGroups.
//
// The group is built from groupTemplate (a JSON object value) plus a freshly
// assigned tests array.
func appendNewGroup(root RawObject, groupTemplate jsontext.Value, tests []jsontext.Value) (RawObject, error) {
	group, err := parseObject(groupTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing groupTemplate: %w", err)
	}
	if _, exists := group.Get("tests"); exists {
		return nil, errors.New("groupTemplate must not contain a tests field; pass tests separately")
	}

	startID, err := nextTcId(root)
	if err != nil {
		return nil, err
	}

	numbered, err := renumberTests(tests, startID)
	if err != nil {
		return nil, err
	}
	group = group.Set("tests", mustMarshalArray(numbered))

	groupVal, err := json.Marshal(&group)
	if err != nil {
		return nil, fmt.Errorf("encoding group: %w", err)
	}

	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	groups = append(groups, jsontext.Value(groupVal))

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// appendIntoGroup appends tests to an existing group identified by source.
//
// source may be "name" or "name@version".
func appendIntoGroup(root RawObject, source string, tests []jsontext.Value) (RawObject, error) {
	filter := ParseSourceFilter(source)

	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}

	var matches []int
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: parsing: %w", i, err)
		}

		match, err := filter.Matches(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		if match {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("--into-group %q matched no group", source)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("--into-group %q matched %d groups; disambiguate with name@version", source, len(matches))
	}

	startID, err := nextTcId(root)
	if err != nil {
		return nil, err
	}
	numbered, err := renumberTests(tests, startID)
	if err != nil {
		return nil, err
	}

	idx := matches[0]
	group, err := parseObject(groups[idx])
	if err != nil {
		return nil, err
	}

	existingTests, err := getTestsArray(group)
	if err != nil {
		return nil, err
	}

	for _, t := range numbered {
		existingTests = append(existingTests, t)
	}
	group = group.Set("tests", mustMarshalArray(existingTests))

	updated, err := json.Marshal(&group)
	if err != nil {
		return nil, err
	}
	groups[idx] = updated

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// mergeNotes inserts each note from add into root.notes.
//
// Conflicting entries (same key, byte-different value) are rejected.
// Insertion order matches the add envelope.
func mergeNotes(root RawObject, add RawObject) (RawObject, error) {
	notesIdx := root.IndexOf("notes")
	var notes RawObject
	if notesIdx >= 0 {
		var err error
		notes, err = parseObject(root[notesIdx].Value)
		if err != nil {
			return nil, fmt.Errorf("parsing notes: %w", err)
		}
	}

	for _, m := range add {
		if existing, ok := notes.Get(m.Name); ok {
			if !jsonEqual(existing, m.Value) {
				return nil, fmt.Errorf("notes[%q] already exists with different content", m.Name)
			}
			continue
		}
		notes = append(notes, ObjectMember[jsontext.Value]{Name: m.Name, Value: m.Value})
	}

	encoded, err := json.Marshal(&notes)
	if err != nil {
		return nil, err
	}

	return root.Set("notes", encoded), nil
}

// recomputeNumberOfTests counts every test across every group and writes the
// total to root.numberOfTests.
//
// If the field doesn't exist, it is created.
func recomputeNumberOfTests(root RawObject) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}

	total := 0
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}

		tests, err := getTestsArray(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		total += len(tests)
	}

	return root.Set("numberOfTests", jsontext.Value(fmt.Sprintf("%d", total))), nil
}

// nextTcId returns max(tcId across all tests in all groups) + 1, or 1 if the
// file currently has no tests.
func nextTcId(root RawObject) (int, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return 0, err
	}

	maxID := 0
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return 0, fmt.Errorf("group %d: %w", i, err)
		}

		tests, err := getTestsArray(group)
		if err != nil {
			return 0, fmt.Errorf("group %d: %w", i, err)
		}

		for j, t := range tests {
			id, err := readTcId(t)
			if err != nil {
				return 0, fmt.Errorf("group %d test %d: %w", i, j, err)
			}
			if id > maxID {
				maxID = id
			}
		}
	}

	return maxID + 1, nil
}

// renumberTests returns a parallel slice with tcId set to startID,
// startID+1, ...
//
// If a test already contains a tcId, it is overwritten (we treat
// operator-supplied tcId as advisory. The tool is authoritative). Each
// returned test has tcId as its first field for consistency with existing
// vectors.
func renumberTests(tests []jsontext.Value, startID int) ([]jsontext.Value, error) {
	out := make([]jsontext.Value, len(tests))
	for i, t := range tests {
		obj, err := parseObject(t)
		if err != nil {
			return nil, fmt.Errorf("test %d: %w", i, err)
		}

		tcId := jsontext.Value(fmt.Sprintf("%d", startID+i))
		if obj.IndexOf("tcId") < 0 {
			obj = obj.InsertAt(0, "tcId", tcId)
		} else {
			obj = obj.Set("tcId", tcId)
		}

		encoded, err := json.Marshal(&obj)
		if err != nil {
			return nil, fmt.Errorf("test %d: %w", i, err)
		}
		out[i] = encoded
	}

	return out, nil
}

// finalizeAndWrite formats root, validates it, and writes atomically.
//
// On validation failure the candidate output is written to vectorPath+".rej"
// and the original (if any) is left untouched.
func finalizeAndWrite(vectorPath string, root RawObject, opts Options) error {
	out, err := marshalObject(root)
	if err != nil {
		return fmt.Errorf("encoding result: %w", err)
	}

	err = LintBytes(out, opts.SchemasFS)
	switch {
	case err == nil, errors.Is(err, ErrIgnoredSchema):
		return writeAtomic(vectorPath, out)
	}

	rej := vectorPath + ".rej"
	if writeErr := os.WriteFile(rej, out, 0o644); writeErr != nil {
		return fmt.Errorf("%w (and failed to write %s: %v)", err, rej, writeErr)
	}

	return fmt.Errorf("%w (candidate written to %s)", err, rej)
}
