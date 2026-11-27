package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// ErrPropertyOrder means a schema lists an object's properties in another
// order than its "required" array. Constrained decoders (Ollama, llama.cpp)
// make the model write keys in the order "properties" lists them, so a
// schema built from a Go map, whose keys json.Marshal sorts, makes the model
// write "end" before it has chosen "start" (#362). "required" is written in
// the order the model should reason in, so it is the order creep sends.
var ErrPropertyOrder = errors.New("schema properties are not in the order of required")

// maxSchemaDepth bounds the walk; creep's schemas nest a few levels.
const maxSchemaDepth = 32

// CheckPropertyOrder walks schema and fails on any object whose
// "properties" keys differ, in order or content, from its "required" array.
// Every object creep sends is closed and requires every property.
func CheckPropertyOrder(schema json.RawMessage) error {
	return checkOrder(schema, 0)
}

func checkOrder(raw json.RawMessage, depth int) error {
	if depth > maxSchemaDepth {
		return fmt.Errorf("%w: nested over %d levels", ErrPropertyOrder, maxSchemaDepth)
	}
	t := bytes.TrimSpace(raw)
	switch {
	case len(t) == 0:
		return nil
	case t[0] == '[':
		var items []json.RawMessage
		if err := json.Unmarshal(t, &items); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
		return checkEach(items, depth)
	case t[0] != '{':
		return nil
	}
	keys, values, err := orderedObject(t)
	if err != nil {
		return err
	}
	if err := checkObject(values); err != nil {
		return err
	}
	ordered := make([]json.RawMessage, len(keys))
	for i, k := range keys {
		ordered[i] = values[k]
	}
	return checkEach(ordered, depth)
}

func checkEach(items []json.RawMessage, depth int) error {
	for _, v := range items {
		if err := checkOrder(v, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// checkObject compares one schema object's properties with its required.
func checkObject(values map[string]json.RawMessage) error {
	props, ok := values["properties"]
	if !ok || bytes.TrimSpace(props)[0] != '{' {
		return nil
	}
	names, _, err := orderedObject(props)
	if err != nil {
		return err
	}
	var required []string
	if raw, ok := values["required"]; ok {
		if err := json.Unmarshal(raw, &required); err != nil {
			return fmt.Errorf("schema required: %w", err)
		}
	}
	if !slices.Equal(names, required) {
		return ErrPropertyOrder
	}
	return nil
}

// orderedObject decodes one JSON object, keeping its key order.
func orderedObject(raw []byte) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return nil, nil, fmt.Errorf("schema: %w", err)
	}
	var keys []string
	values := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("schema: %w", err)
		}
		key, _ := tok.(string) // an object key is always a string
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("schema: %w", err)
		}
		if _, dup := values[key]; dup {
			return nil, nil, fmt.Errorf("%w: duplicate key", ErrPropertyOrder)
		}
		keys = append(keys, key)
		values[key] = v
	}
	return keys, values, nil
}
