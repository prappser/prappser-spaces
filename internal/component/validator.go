package component

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

//go:embed schemas/component/*.schema.json schemas/template/*.schema.json
var schemaFS embed.FS

var (
	ErrUnknownComponentType = errors.New("unknown component type")
	ErrInvalidData          = errors.New("invalid data")
)

const (
	commonSchemaFile = "common.v1.schema.json"
	templateSchema   = "https://prappser.app/schemas/template/template-doc.v1.schema.json"
)

type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type ValidationErrors []FieldError

func (e ValidationErrors) Error() string {
	parts := make([]string, len(e))
	for i, f := range e {
		parts[i] = fmt.Sprintf("at %q: %s", f.Path, f.Message)
	}
	return ErrInvalidData.Error() + ": " + strings.Join(parts, "; ")
}

func (e ValidationErrors) Unwrap() error { return ErrInvalidData }

type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema %q is not allowed", url)
}

const (
	AccessManage = "manage"
	AccessMember = "member"
	AccessNone   = "none"
)

type Flag struct {
	Name    string
	Default bool
}

func (f Flag) On(data map[string]any) bool {
	if b, ok := data[f.Name].(bool); ok {
		return b
	}
	return f.Default
}

type Access struct {
	Level   string
	Gate    *Flag
	Unless  *Flag
	Fields  map[string]*Flag
	Append  bool
	Author  string
	Content string
	own     *regexp.Regexp
}

func (a Access) OwnKey(key, publicKey string) bool {
	if a.own == nil {
		return true
	}
	m := a.own.FindStringSubmatch(key)
	return m != nil && m[1] == publicKey
}

type TypeInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type rule struct {
	re     *regexp.Regexp
	merge  string
	access Access
}

type rules struct {
	props    map[string]rule
	patterns []rule
}

// Build once, safe for concurrent use.
type Validator struct {
	compiler     *jsonschema.Compiler
	components   map[string]*jsonschema.Schema
	componentIDs map[string]string
	template     *jsonschema.Schema
	rules        map[string]rules
	content      map[[2]string]*jsonschema.Schema
	raw          map[string][]byte
	desc         map[string]string
}

type componentSchema struct {
	name string
	id   string
}

var mergeModes = map[string]bool{"single": true, "per-entry": true, "per-member": true}

func NewValidator() (*Validator, error) {
	return newValidator(schemaFS)
}

func newValidator(fsys fs.FS) (*Validator, error) {
	v := &Validator{
		compiler:     jsonschema.NewCompiler(),
		components:   map[string]*jsonschema.Schema{},
		componentIDs: map[string]string{},
		rules:        map[string]rules{},
		content:      map[[2]string]*jsonschema.Schema{},
		raw:          map[string][]byte{},
		desc:         map[string]string{},
	}

	v.compiler.UseLoader(denyLoader{})

	var pending []componentSchema
	for _, dir := range []string{"schemas/component", "schemas/template"} {
		files, err := fs.Glob(fsys, dir+"/*.schema.json")
		if err != nil {
			return nil, fmt.Errorf("failed to list schemas in %s: %w", dir, err)
		}
		for _, file := range files {
			raw, err := fs.ReadFile(fsys, file)
			if err != nil {
				return nil, fmt.Errorf("failed to read schema %s: %w", file, err)
			}
			parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return nil, fmt.Errorf("failed to parse schema %s: %w", file, err)
			}
			doc, _ := parsed.(map[string]any)
			id, _ := doc["$id"].(string)
			if id == "" {
				return nil, fmt.Errorf("schema %s has no $id", file)
			}
			if err := v.compiler.AddResource(id, doc); err != nil {
				return nil, fmt.Errorf("failed to add schema %s: %w", file, err)
			}

			switch {
			case dir == "schemas/template":
				pending = append(pending, componentSchema{id: id})
			case path.Base(file) != commonSchemaFile:
				name := strings.TrimSuffix(path.Base(file), ".v1.schema.json")
				name = strings.ToUpper(name[:1]) + name[1:]
				rs, err := parseRules(doc)
				if err != nil {
					return nil, fmt.Errorf("failed to read x-merge or x-access of %s: %w", file, err)
				}
				v.rules[name] = rs
				v.raw[name] = raw
				v.desc[name], _ = doc["description"].(string)
				pending = append(pending, componentSchema{name: name, id: id})
			}
		}
	}

	for _, c := range pending {
		sch, err := v.compiler.Compile(c.id)
		if err != nil {
			return nil, fmt.Errorf("failed to compile schema %s: %w", c.id, err)
		}
		if c.name == "" {
			v.template = sch
			continue
		}
		v.components[c.name] = sch
		v.componentIDs[c.name] = c.id
		rs := v.rules[c.name]
		all := append([]rule{}, rs.patterns...)
		for _, r := range rs.props {
			all = append(all, r)
		}
		for _, r := range all {
			def := r.access.Content
			if _, done := v.content[[2]string{c.name, def}]; def == "" || done {
				continue
			}
			cs, err := v.compiler.Compile(c.id + "#/$defs/" + def)
			if err != nil {
				return nil, fmt.Errorf("failed to compile content %q of schema %s: %w", def, c.id, err)
			}
			v.content[[2]string{c.name, def}] = cs
		}
	}
	if v.template == nil {
		return nil, errors.New("template doc schema not found")
	}
	return v, nil
}

func parseFlag(props map[string]any, name string) (*Flag, error) {
	p, _ := props[name].(map[string]any)
	def, ok := p["default"].(bool)
	if !ok {
		return nil, fmt.Errorf("flag %s has no boolean default", name)
	}
	return &Flag{Name: name, Default: def}, nil
}

func parseAccess(raw any, props, defs map[string]any) (Access, error) {
	switch t := raw.(type) {
	case string:
		if t != AccessManage && t != AccessMember && t != AccessNone {
			return Access{}, fmt.Errorf("invalid x-access %q", t)
		}
		return Access{Level: t}, nil
	case map[string]any:
		a := Access{Level: AccessMember}
		for k, val := range t {
			var err error
			switch k {
			case "gate":
				name, ok := val.(string)
				if !ok {
					return Access{}, errors.New("x-access gate must be a string")
				}
				a.Gate, err = parseFlag(props, name)
			case "unless":
				name, ok := val.(string)
				if !ok {
					return Access{}, errors.New("x-access unless must be a string")
				}
				a.Unless, err = parseFlag(props, name)
			case "fields":
				fields, ok := val.(map[string]any)
				if !ok {
					return Access{}, errors.New("x-access fields must be an object")
				}
				a.Fields = map[string]*Flag{}
				for field, fv := range fields {
					if fv == nil {
						a.Fields[field] = nil
						continue
					}
					name, ok := fv.(string)
					if !ok {
						return Access{}, fmt.Errorf("x-access field %s must be a string or null", field)
					}
					if a.Fields[field], err = parseFlag(props, name); err != nil {
						break
					}
				}
			case "append":
				b, ok := val.(bool)
				if !ok {
					return Access{}, errors.New("x-access append must be a boolean")
				}
				a.Append = b
			case "author":
				if a.Author, _ = val.(string); a.Author == "" {
					return Access{}, errors.New("x-access author must be a string")
				}
			case "content":
				if a.Content, _ = val.(string); a.Content == "" {
					return Access{}, errors.New("x-access content must be a string")
				}
				if _, ok := defs[a.Content]; !ok {
					return Access{}, fmt.Errorf("x-access content %q is not in $defs", a.Content)
				}
			default:
				return Access{}, fmt.Errorf("unknown x-access key %q", k)
			}
			if err != nil {
				return Access{}, err
			}
		}
		return a, nil
	}
	return Access{}, errors.New("missing x-access")
}

func parseRule(key string, entry any, props, defs map[string]any, pattern bool) (rule, error) {
	m, _ := entry.(map[string]any)
	acc, err := parseAccess(m["x-access"], props, defs)
	if err != nil {
		return rule{}, fmt.Errorf("%q: %w", key, err)
	}
	r := rule{access: acc}
	if raw, ok := m["x-merge"]; ok {
		mode, _ := raw.(string)
		if !mergeModes[mode] {
			return rule{}, fmt.Errorf("invalid x-merge %v on %q", raw, key)
		}
		r.merge = mode
	}
	if !pattern {
		if r.merge == "per-member" {
			return rule{}, fmt.Errorf("per-member property %q must be a pattern ending in .+$", key)
		}
		return r, nil
	}
	if r.re, err = regexp.Compile(key); err != nil {
		return rule{}, fmt.Errorf("invalid pattern %q: %w", key, err)
	}
	if r.merge == "per-member" {
		own, ok := strings.CutSuffix(key, ".+$")
		if !ok {
			return rule{}, fmt.Errorf("per-member pattern %q must end in .+$", key)
		}
		if r.access.own, err = regexp.Compile(own + "(.+)$"); err != nil {
			return rule{}, fmt.Errorf("invalid pattern %q: %w", key, err)
		}
	}
	return r, nil
}

func parseRules(doc map[string]any) (rules, error) {
	rs := rules{props: map[string]rule{}}
	props, _ := doc["properties"].(map[string]any)
	defs, _ := doc["$defs"].(map[string]any)
	for k, e := range props {
		r, err := parseRule(k, e, props, defs, false)
		if err != nil {
			return rules{}, err
		}
		rs.props[k] = r
	}
	pats, _ := doc["patternProperties"].(map[string]any)
	keys := make([]string, 0, len(pats))
	for p := range pats {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		r, err := parseRule(p, pats[p], props, defs, true)
		if err != nil {
			return rules{}, err
		}
		rs.patterns = append(rs.patterns, r)
	}
	return rs, nil
}

func (v *Validator) ValidateComponentData(componentType string, data map[string]any) error {
	sch, ok := v.components[componentType]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownComponentType, componentType)
	}
	return validate(sch, data, false)
}

// ValidateComponentKeys validates a partial write: root-level required errors are dropped, since the data holds only the keys being written.
func (v *Validator) ValidateComponentKeys(componentType string, data map[string]any) error {
	sch, ok := v.components[componentType]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownComponentType, componentType)
	}
	return validate(sch, data, true)
}

func (v *Validator) ValidateContent(componentType, def, raw string) error {
	sch, ok := v.content[[2]string{componentType, def}]
	if !ok {
		return fmt.Errorf("%w: %q has no content %q", ErrUnknownComponentType, componentType, def)
	}
	decoded, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		return ValidationErrors{{Path: "", Message: "not valid JSON"}}
	}
	return validate(sch, decoded, false)
}

func (v *Validator) ValidateTemplateDoc(doc map[string]any) error {
	return validate(v.template, doc, false)
}

func (v *Validator) Types() []TypeInfo {
	out := make([]TypeInfo, 0, len(v.components))
	for name := range v.components {
		out = append(out, TypeInfo{Type: name, Description: v.desc[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func (v *Validator) Schema(componentType string) (json.RawMessage, bool) {
	raw, ok := v.raw[componentType]
	return raw, ok
}

func validate(sch *jsonschema.Schema, data any, partial bool) error {
	err := sch.Validate(data)
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return fmt.Errorf("%w: %w", ErrInvalidData, err)
	}
	var out ValidationErrors
	collectLeaves(verr, message.NewPrinter(language.English), partial, &out)
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func collectLeaves(e *jsonschema.ValidationError, p *message.Printer, partial bool, out *ValidationErrors) {
	if len(e.Causes) == 0 {
		if _, required := e.ErrorKind.(*kind.Required); partial && required && len(e.InstanceLocation) == 0 {
			return
		}
		*out = append(*out, FieldError{Path: jsonPointer(e.InstanceLocation), Message: e.ErrorKind.LocalizedString(p)})
		return
	}
	for _, c := range e.Causes {
		collectLeaves(c, p, partial, out)
	}
}

var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

func jsonPointer(loc []string) string {
	var sb strings.Builder
	for _, t := range loc {
		sb.WriteByte('/')
		sb.WriteString(pointerEscaper.Replace(t))
	}
	return sb.String()
}

// resolve finds a key's rule: exact properties win, then the first matching pattern (in sorted pattern order).
func (v *Validator) resolve(componentType, key string) (rule, bool) {
	rs, ok := v.rules[componentType]
	if !ok {
		return rule{}, false
	}
	if r, ok := rs.props[key]; ok {
		return r, true
	}
	for _, r := range rs.patterns {
		if r.re.MatchString(key) {
			return r, true
		}
	}
	return rule{}, false
}

func (v *Validator) MergeMode(componentType, key string) (string, bool) {
	r, ok := v.resolve(componentType, key)
	return r.merge, ok && r.merge != ""
}

func (v *Validator) Access(componentType, key string) (Access, bool) {
	r, ok := v.resolve(componentType, key)
	return r.access, ok
}
