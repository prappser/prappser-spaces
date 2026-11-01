//go:build integration

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestAgentRead_ShouldBeWiredAndOwnerOnly(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	path := "/applications/" + moveAppID + "/agent-read"
	enabled := func() bool {
		var on bool
		require.NoError(t, f.db.QueryRow(`SELECT agent_read_enabled FROM applications WHERE id = $1`, moveAppID).Scan(&on))
		return on
	}

	// when
	member := f.doJSON("PUT", path, moveMemberPK, map[string]any{"enabled": false})
	afterMember := enabled()
	owner := f.doJSON("PUT", path, moveOwnerPK, map[string]any{"enabled": false})
	wrongMethod := f.doJSON("POST", path, moveOwnerPK, nil)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, member.Response.StatusCode())
	assert.True(t, afterMember)
	assert.Equal(t, fasthttp.StatusOK, owner.Response.StatusCode())
	assert.JSONEq(t, `{"agentReadEnabled":false}`, string(owner.Response.Body()))
	assert.False(t, enabled())
	assert.Equal(t, fasthttp.StatusMethodNotAllowed, wrongMethod.Response.StatusCode())
}
