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

type patternMerge struct {
	re   *regexp.Regexp
	mode string
}

type mergeRules struct {
	props    map[string]string
	patterns []patternMerge
}

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
	v := &Validator{
		compiler:     jsonschema.NewCompiler(),
		components:   map[string]*jsonschema.Schema{},
		componentIDs: map[string]string{},
		merge:        map[string]mergeRules{},
	}

	var pending []componentSchema
	for _, dir := range []string{"schemas/component", "schemas/template"} {
		files, err := fs.Glob(schemaFS, dir+"/*.schema.json")
		if err != nil {
			return nil, fmt.Errorf("failed to list schemas in %s: %w", dir, err)
		}
		for _, file := range files {
			raw, err := schemaFS.ReadFile(file)
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
	if err := sch.Validate(data); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidData, err)
	}
	return nil
}

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
