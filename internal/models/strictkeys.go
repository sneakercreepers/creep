package models

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// Rejection reasons of the key pass. Fixed text: no key from the reply
// reaches a retry prompt through them.
const (
	reasonDuplicateKey = "it had a duplicate key"
	reasonKeyCase      = "it had a key that does not exactly match the schema"
	// reasonAmbiguous is creep's bug, not the model's: the output type gives
	// one JSON name to two fields, so every reply to it is refused.
	reasonAmbiguous = "its schema type gives one JSON name to two fields"
)

// strictKeys reports why content, already decoded into a t, must still be
// rejected: encoding/json lets the last of duplicate keys win and matches
// keys case-insensitively, so {"verdict":"a","Verdict":"b"} would decode.
// It walks every token once, so its cost is linear in content.
func strictKeys(content []byte, t reflect.Type) string {
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	return walkValue(dec, t)
}

// walkValue checks the next value against t. A nil t (interface, map key
// space, raw JSON) allows any key but still refuses duplicates. Decode
// errors are left to the caller's decode, which already passed.
func walkValue(dec *json.Decoder, t reflect.Type) string {
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec, t)
	case json.Delim('['):
		return walkArray(dec, elemType(t))
	}
	return ""
}

func walkObject(dec *json.Decoder, t reflect.Type) string {
	fields, closed, ok := objectFields(t)
	if !ok {
		return reasonAmbiguous
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return ""
		}
		if seen[key] {
			return reasonDuplicateKey
		}
		seen[key] = true
		next, known := fields[key]
		if closed && !known {
			return reasonKeyCase
		}
		if !closed {
			next = valueType(t)
		}
		if r := walkValue(dec, next); r != "" {
			return r
		}
	}
	_, _ = dec.Token() // the closing brace
	return ""
}

func walkArray(dec *json.Decoder, elem reflect.Type) string {
	for dec.More() {
		if r := walkValue(dec, elem); r != "" {
			return r
		}
	}
	_, _ = dec.Token() // the closing bracket
	return ""
}

// unmarshalerType marks structs that decode themselves; their keys are
// theirs to check.
var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// objectFields maps each exact JSON name of struct t to its field type.
// closed is false when t is not a struct, so any key is allowed. ok is false
// when two fields share a JSON name: encoding/json would pick one by depth
// and tags, and refusing the type is simpler than copying that rule.
func objectFields(t reflect.Type) (fields map[string]reflect.Type, closed, ok bool) {
	t = deref(t)
	if t == nil || t.Kind() != reflect.Struct || reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil, false, true
	}
	fields = map[string]reflect.Type{}
	return fields, true, addFields(fields, t)
}

// addFields adds t's JSON names to fields, promoting those of embedded
// structs, and reports false when a name is already taken.
func addFields(fields map[string]reflect.Type, t reflect.Type) bool {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case tag == "-":
			continue
		case f.Anonymous && name == "" && deref(f.Type).Kind() == reflect.Struct:
			if !addFields(fields, deref(f.Type)) {
				return false
			}
			continue
		case !f.IsExported():
			continue
		case name == "":
			name = f.Name
		}
		if _, taken := fields[name]; taken {
			return false
		}
		fields[name] = f.Type
	}
	return true
}

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func elemType(t reflect.Type) reflect.Type {
	t = deref(t)
	if t == nil || (t.Kind() != reflect.Slice && t.Kind() != reflect.Array) {
		return nil
	}
	return t.Elem()
}

func valueType(t reflect.Type) reflect.Type {
	t = deref(t)
	if t == nil || t.Kind() != reflect.Map {
		return nil
	}
	return t.Elem()
}
