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

func TestPickComponent_ShouldUseTheOnlyChat(t *testing.T) {
	// given
	app := appWithChats("c1")

	// when
	chat, choices, err := pickComponent(app, chatComponentName, "")

	// then
	assert.NoError(t, err)
	assert.Nil(t, choices)
	assert.Equal(t, "c1", chat.ID)
}

func TestPickComponent_ShouldReturnChoicesWhenSeveral(t *testing.T) {
	// given
	app := appWithChats("c1", "c2")

	// when
	chat, choices, err := pickComponent(app, chatComponentName, "")

	// then
	assert.NoError(t, err)
	assert.Nil(t, chat)
	assert.Len(t, choices, 2)
}

func TestPickComponent_ShouldRejectNonChatComponentID(t *testing.T) {
	// given
	app := appWithChats("c1")

	// when
	_, _, err := pickComponent(app, chatComponentName, "notes")

	// then
	assert.Error(t, err)
}

func TestPickComponent_ShouldReportChatOffWhenNone(t *testing.T) {
	// given
	app := appWithChats()

	// when
	_, _, err := pickComponent(app, chatComponentName, "")

	// then
	assert.ErrorIs(t, err, errChatOff)
}
