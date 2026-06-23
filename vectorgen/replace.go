package vectorgen

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
)

// Replace swaps the single group matching source (and optional version) in
// the vector file at vectorPath with a fresh group built from env's
// GroupTemplate and Tests. The new group is inserted at the original group's
// position. Every test in the file is renumbered sequentially from 1 in file
// order; numberOfTests is recomputed.
//
// Errors:
//   - The source filter matches zero or more than one group.
//   - The envelope has top-level metadata fields set (Algorithm, Schema,
//     Header) — those are only meaningful when creating a new file.
//   - The envelope has IntoGroup set — that's an Add-only mode.
//
// On schema-validation failure the candidate output is written to
// vectorPath+".rej" and the original is left untouched.
func Replace(vectorPath string, env AddEnvelope, source, version string, opts Options) error {
	if source == "" {
		return errors.New("source is required")
	}
	if len(env.Tests) == 0 {
		return errors.New("envelope.tests is empty")
	}
	if len(env.GroupTemplate) == 0 {
		return errors.New("envelope.groupTemplate is required")
	}
	if env.Algorithm != "" || env.Schema != "" || len(env.Header) > 0 {
		return errors.New("envelope must not set algorithm/schema/header for replace (those are for new files)")
	}
	if env.IntoGroup != "" {
		return errors.New("envelope.intoGroup is for add, not replace")
	}

	existing, err := os.ReadFile(vectorPath)
	if err != nil {
		return err
	}
	root, err := parseObject(existing)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", vectorPath, err)
	}

	root, err = replaceGroup(root, source, version, env.GroupTemplate, env.Tests)
	if err != nil {
		return err
	}

	if len(env.Notes) > 0 {
		root, err = mergeNotes(root, env.Notes)
		if err != nil {
			return err
		}
	}

	root, err = renumberAllTests(root)
	if err != nil {
		return err
	}

	root, err = recomputeNumberOfTests(root)
	if err != nil {
		return err
	}

	return finalizeAndWrite(vectorPath, root, opts)
}

// replaceGroup finds the single group matching source[@version] and swaps it
// for a freshly built group (template + tests) at the same position.
func replaceGroup(root RawObject, source, version string, groupTemplate jsontext.Value, tests []jsontext.Value) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}

	var matches []int
	for i, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		match, err := groupMatchesSource(group, source, version)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", i, err)
		}
		if match {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("source %q matched no group", sourceLabel(source, version))
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("source %q matched %d groups; disambiguate with name@version", sourceLabel(source, version), len(matches))
	}

	newGroup, err := parseObject(groupTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing groupTemplate: %w", err)
	}
	if _, exists := newGroup.Get("tests"); exists {
		return nil, errors.New("groupTemplate must not contain a tests field; pass tests separately")
	}
	// Insert tests with placeholder numbering; renumberAllTests will rewrite
	// them in their final positions based on file order.
	numbered, err := renumberTests(tests, 1)
	if err != nil {
		return nil, err
	}
	newGroup = newGroup.Set("tests", mustMarshalArray(numbered))
	encoded, err := json.Marshal(&newGroup)
	if err != nil {
		return nil, err
	}
	groups[matches[0]] = encoded

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// renumberAllTests rewrites every test's tcId across every group, starting
// from 1 and incrementing in file order. Used by Replace because a swapped
// group may differ in size from the one it replaced.
func renumberAllTests(root RawObject) (RawObject, error) {
	groups, err := getTestGroups(root)
	if err != nil {
		return nil, err
	}
	id := 1
	for gi, g := range groups {
		group, err := parseObject(g)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		tests, err := getTestsArray(group)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}
		if len(tests) == 0 {
			continue
		}

		renumbered, err := renumberTests(tests, id)
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", gi, err)
		}

		id += len(tests)
		group = group.Set("tests", mustMarshalArray(renumbered))

		encoded, err := json.Marshal(&group)
		if err != nil {
			return nil, err
		}
		groups[gi] = encoded
	}

	return root.Set("testGroups", mustMarshalArray(groups)), nil
}

// sourceLabel formats a source filter for error messages.
func sourceLabel(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}
