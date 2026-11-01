package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/application"
)

func appWithChats(ids ...string) *application.Application {
	comps := []application.Component{{ID: "notes", Name: "Notes"}}
	for _, id := range ids {
		comps = append(comps, application.Component{ID: id, Name: "Chat"})
	}
	return &application.Application{ComponentGroups: []application.ComponentGroup{{Components: comps}}}
}

func TestPickChat_ShouldUseTheOnlyChat(t *testing.T) {
	// given
	app := appWithChats("c1")

	// when
	chat, choices, err := pickChat(app, "")

	// then
	assert.NoError(t, err)
	assert.Nil(t, choices)
	assert.Equal(t, "c1", chat.ID)
}

func TestPickChat_ShouldReturnChoicesWhenSeveral(t *testing.T) {
	// given
	app := appWithChats("c1", "c2")

	// when
	chat, choices, err := pickChat(app, "")

	// then
	assert.NoError(t, err)
	assert.Nil(t, chat)
	assert.Len(t, choices, 2)
}

func TestPickChat_ShouldRejectNonChatComponentID(t *testing.T) {
	// given
	app := appWithChats("c1")

	// when
	_, _, err := pickChat(app, "notes")

	// then
	assert.Error(t, err)
}

func TestPickChat_ShouldReportChatOffWhenNone(t *testing.T) {
	// given
	app := appWithChats()

	// when
	_, _, err := pickChat(app, "")

	// then
	assert.ErrorIs(t, err, errChatOff)
}
