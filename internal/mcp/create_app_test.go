package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/application"
)

func docWith(comp map[string]any) map[string]any {
	return map[string]any{"groups": []any{map[string]any{"components": []any{comp}}}}
}

func paths(doc map[string]any) []string {
	var out []string
	for _, f := range templateReferenceErrors(doc) {
		out = append(out, f.Path)
	}
	return out
}

func TestLimitErrors_ShouldAcceptNameAtLimit(t *testing.T) {
	// given
	doc := map[string]any{"name": " " + strings.Repeat("a", 62) + "😀 "}

	// when
	fields := limitErrors(doc)

	// then
	assert.Empty(t, fields)
}

func TestLimitErrors_ShouldCountUTF16UnitsNotCodePoints(t *testing.T) {
	// given
	name := strings.Repeat("a", 63) + "😀"
	doc := map[string]any{"name": name}

	// when
	fields := limitErrors(doc)

	// then
	assert.Len(t, []rune(name), 64)
	assert.Len(t, fields, 1)
	assert.Equal(t, "/name", fields[0].Path)
}

func TestLimitErrors_ShouldRejectBlankName(t *testing.T) {
	// given
	doc := map[string]any{"name": "   "}

	// when
	fields := limitErrors(doc)

	// then
	assert.Len(t, fields, 1)
	assert.Equal(t, "/name", fields[0].Path)
}

func TestDocSizeErrors_ShouldRejectOver64KiBWithByteCount(t *testing.T) {
	// given
	small := map[string]any{"name": "x"}
	big := map[string]any{"name": strings.Repeat("x", maxTemplateDocBytes)}

	// when
	small1 := docSizeErrors(small)
	big1 := docSizeErrors(big)

	// then
	assert.Empty(t, small1)
	require.Len(t, big1, 1)
	assert.Equal(t, "", big1[0].Path)
	assert.Equal(t, "template is 65547 bytes, the maximum is 65536", big1[0].Message)
}

func TestCreateAppResult_ShouldWarnNotToRetryWhenEventFailed(t *testing.T) {
	// given
	app := &application.Application{ID: "a1", Name: "Trip"}

	// when
	failed, _ := json.Marshal(createAppResult(app, errors.New("boom")))
	ok, _ := json.Marshal(createAppResult(app, nil))

	// then
	assert.Contains(t, string(failed), `"appId":"a1"`)
	assert.Contains(t, string(failed), "do not retry")
	assert.JSONEq(t, `{"appId":"a1","name":"Trip"}`, string(ok))
}

func TestTemplateReferenceErrors_ShouldAcceptTemplateWithoutReferences(t *testing.T) {
	// given
	doc := map[string]any{"groups": []any{map[string]any{"components": []any{
		map[string]any{"type": "Checklist", "data": map[string]any{"item_a": map[string]any{"title": "t", "checked": false, "assignedMemberId": nil, "attachmentIds": []any{}, "detailsDocument": []any{map[string]any{"insert": "hi\n"}}}}},
		map[string]any{"type": "Map", "data": map[string]any{"markers": []any{map[string]any{"id": "1", "createdBy": ""}}, "otherUsers": []any{}}},
		map[string]any{"type": "Files", "data": map[string]any{"items": []any{}}},
		map[string]any{"type": "Text", "data": map[string]any{"document": []any{map[string]any{"insert": "hi\n"}}}},
	}}}}

	// when
	fields := templateReferenceErrors(doc)

	// then
	assert.Empty(t, fields)
}

func TestTemplateReferenceErrors_ShouldRejectChecklistMemberAttachmentAndMedia(t *testing.T) {
	// given
	doc := docWith(map[string]any{"type": "Checklist", "data": map[string]any{"item_x": map[string]any{
		"title": "t", "checked": false,
		"assignedMemberId": "pk",
		"attachmentIds":    []any{"f"},
		"detailsDocument":  []any{map[string]any{"insert": "a"}, map[string]any{"insert": map[string]any{"image": "u"}}},
	}}})

	// when
	got := paths(doc)

	// then
	base := "/groups/0/components/0/data/item_x"
	assert.Equal(t, []string{base + "/assignedMemberId", base + "/attachmentIds", base + "/detailsDocument/1/insert"}, got)
}

func TestTemplateReferenceErrors_ShouldRejectMapAuthorAndLiveLocations(t *testing.T) {
	// given
	doc := docWith(map[string]any{"type": "Map", "data": map[string]any{
		"markers":    []any{map[string]any{"id": "1", "createdBy": ""}, map[string]any{"id": "2", "createdBy": "pk"}},
		"otherUsers": []any{map[string]any{"userId": "u"}},
	}})

	// when
	got := paths(doc)

	// then
	base := "/groups/0/components/0/data"
	assert.ElementsMatch(t, []string{base + "/markers/1/createdBy", base + "/otherUsers"}, got)
}

func TestTemplateReferenceErrors_ShouldRejectFiles(t *testing.T) {
	// given
	doc := docWith(map[string]any{"type": "Files", "data": map[string]any{"items": []any{map[string]any{"id": "1"}}}})

	// when
	got := paths(doc)

	// then
	assert.Equal(t, []string{"/groups/0/components/0/data/items"}, got)
}

func TestTemplateReferenceErrors_ShouldRejectTextVideoEmbed(t *testing.T) {
	// given
	doc := docWith(map[string]any{"type": "Text", "data": map[string]any{"document": []any{map[string]any{"insert": map[string]any{"video": "u"}}}}})

	// when
	got := paths(doc)

	// then
	assert.Equal(t, []string{"/groups/0/components/0/data/document/0/insert"}, got)
}

func TestTemplateReferenceErrors_ShouldRejectTextLegacyObjectDocument(t *testing.T) {
	// given
	legacy := map[string]any{"children": []any{map[string]any{"delta": []any{map[string]any{"insert": map[string]any{"image": "u"}}}}}}
	doc := docWith(map[string]any{"type": "Text", "data": map[string]any{"document": legacy}})

	// when
	got := paths(doc)

	// then
	assert.Equal(t, []string{"/groups/0/components/0/data/document"}, got)
}
