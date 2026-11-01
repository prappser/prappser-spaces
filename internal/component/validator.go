package component

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
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

type patternMerge struct {
	re   *regexp.Regexp
	mode string
}

type mergeRules struct {
	props    map[string]string
	patterns []patternMerge
}

// Build once, safe for concurrent use.
type Validator struct {
	compiler     *jsonschema.Compiler
	components   map[string]*jsonschema.Schema
	componentIDs map[string]string
	template     *jsonschema.Schema
	merge        map[string]mergeRules
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
		merge:        map[string]mergeRules{},
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
				rules, err := parseMergeRules(doc)
				if err != nil {
					return nil, fmt.Errorf("failed to read x-merge of %s: %w", file, err)
				}
				v.merge[name] = rules
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
	}
	if v.template == nil {
		return nil, errors.New("template doc schema not found")
	}
	return v, nil
}

func mergeMode(key string, entry any) (string, bool, error) {
	m, _ := entry.(map[string]any)
	raw, ok := m["x-merge"]
	if !ok {
		return "", false, nil
	}
	mode, _ := raw.(string)
	if !mergeModes[mode] {
		return "", false, fmt.Errorf("invalid x-merge %v on %q", raw, key)
	}
	return mode, true, nil
}

func parseMergeRules(doc map[string]any) (mergeRules, error) {
	rules := mergeRules{props: map[string]string{}}
	props, _ := doc["properties"].(map[string]any)
	for k, e := range props {
		mode, ok, err := mergeMode(k, e)
		if err != nil {
			return mergeRules{}, err
		}
		if ok {
			rules.props[k] = mode
		}
	}
	pats, _ := doc["patternProperties"].(map[string]any)
	keys := make([]string, 0, len(pats))
	for p := range pats {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		mode, ok, err := mergeMode(p, pats[p])
		if err != nil {
			return mergeRules{}, err
		}
		if !ok {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return mergeRules{}, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		rules.patterns = append(rules.patterns, patternMerge{re: re, mode: mode})
	}
	return rules, nil
}

func (v *Validator) ValidateComponentData(componentType string, data map[string]any) error {
	sch, ok := v.components[componentType]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownComponentType, componentType)
	}
	return validate(sch, data)
}

func (v *Validator) ValidateTemplateDoc(doc map[string]any) error {
	return validate(v.template, doc)
}

func validate(sch *jsonschema.Schema, data map[string]any) error {
	err := sch.Validate(data)
	if err == nil {
		return nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return fmt.Errorf("%w: %w", ErrInvalidData, err)
	}
	var out ValidationErrors
	collectLeaves(verr, message.NewPrinter(language.English), &out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func collectLeaves(e *jsonschema.ValidationError, p *message.Printer, out *ValidationErrors) {
	if len(e.Causes) == 0 {
		*out = append(*out, FieldError{Path: jsonPointer(e.InstanceLocation), Message: e.ErrorKind.LocalizedString(p)})
		return
	}
	for _, c := range e.Causes {
		collectLeaves(c, p, out)
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

// MergeMode resolves a key: exact properties win, then the first matching pattern (in sorted pattern order).
func (v *Validator) MergeMode(componentType, key string) (string, bool) {
	rules, ok := v.merge[componentType]
	if !ok {
		return "", false
	}
	if mode, ok := rules.props[key]; ok {
		return mode, true
	}
	for _, p := range rules.patterns {
		if p.re.MatchString(key) {
			return p.mode, true
		}
	}
	return "", false
}
