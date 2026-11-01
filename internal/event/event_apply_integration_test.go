//go:build integration

package event

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

type countingBroadcaster struct{ app atomic.Int32 }

func (b *countingBroadcaster) BroadcastToApplication(string, *Event) { b.app.Add(1) }
func (b *countingBroadcaster) BroadcastToUser(string, *Event)        {}

func connectApply(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t, "event")
	t.Cleanup(func() { db.Close() })
	return db
}

func seedComponent(t *testing.T, appRepo *application.Repository, appID, componentID string) {
	t.Helper()
	require.NoError(t, appRepo.CreateComponentGroup(&application.ComponentGroup{ID: appID + "-group", ApplicationID: appID, Name: "G"}))
	require.NoError(t, appRepo.CreateComponent(&application.Component{
		ID: componentID, ComponentGroupID: appID + "-group", ApplicationID: appID, Name: "C",
		Data: map[string]interface{}{"title": "original"},
	}))
}

func componentDataEvent(id, appID, creator, componentID, value string) *Event {
	return &Event{
		ID:               id,
		Type:             EventTypeComponentDataChanged,
		CreatorPublicKey: creator,
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data: map[string]interface{}{
			"applicationId": appID,
			"componentId":   componentID,
			"changedFields": map[string]interface{}{"title": map[string]interface{}{"oldValue": "original", "newValue": value}},
		},
	}
}

func editModeEvent(id, appID, creator string, changes ...map[string]interface{}) *Event {
	list := make([]interface{}, len(changes))
	for i, c := range changes {
		list[i] = c
	}
	return &Event{
		ID:               id,
		Type:             EventTypeApplicationAfterEditModeChanged,
		CreatorPublicKey: creator,
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data:             map[string]interface{}{"version": 1, "applicationId": appID, "changes": list},
	}
}

func countEvents(t *testing.T, db *sql.DB, where string, args ...interface{}) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM events WHERE "+where, args...).Scan(&n))
	return n
}

func componentData(t *testing.T, db *sql.DB, componentID string) string {
	t.Helper()
	var data string
	require.NoError(t, db.QueryRow("SELECT data FROM components WHERE id = $1", componentID).Scan(&data))
	return data
}

func lastSequence(t *testing.T, db *sql.DB, appID string) int64 {
	t.Helper()
	var seq sql.NullInt64
	require.NoError(t, db.QueryRow("SELECT last_sequence FROM applications WHERE id = $1", appID).Scan(&seq))
	return seq.Int64
}

func TestAcceptEvent_ComponentDataChangedOnMissingComponent_ShouldRejectWithoutPersisting(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-missing-comp-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	before := lastSequence(t, db, prefix+"app")

	// when
	_, err := service.AcceptEvent(context.Background(), componentDataEvent(prefix+"evt", prefix+"app", prefix+"member", "no-such-component", "x"), &user.User{PublicKey: prefix + "member"})

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "application_id = $1", prefix+"app"))
	assert.Equal(t, before, lastSequence(t, db, prefix+"app"))
}

func TestAcceptEvent_ComponentDataChangedOnOtherAppsComponent_ShouldReject(t *testing.T) {
	// given
	db := connectApply(t)
	appRepo := seedRoleApp(t, db, "apply-xa-")
	seedRoleApp(t, db, "apply-xb-")
	seedComponent(t, appRepo, "apply-xb-app", "apply-xb-comp")
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	_, err := service.AcceptEvent(context.Background(), componentDataEvent("apply-xa-evt", "apply-xa-app", "apply-xa-member", "apply-xb-comp", "hijacked"), &user.User{PublicKey: "apply-xa-member"})

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Contains(t, componentData(t, db, "apply-xb-comp"), "original")
	assert.Equal(t, 0, countEvents(t, db, "id = $1", "apply-xa-evt"))
}

func TestAcceptEvent_EditModeOnOtherAppsEntities_ShouldNotTouchThem(t *testing.T) {
	// given
	db := connectApply(t)
	appRepo := seedRoleApp(t, db, "apply-ea-")
	seedRoleApp(t, db, "apply-eb-")
	seedComponent(t, appRepo, "apply-ea-app", "apply-ea-comp")
	seedComponent(t, appRepo, "apply-eb-app", "apply-eb-comp")
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	submitter := &user.User{PublicKey: "apply-ea-owner"}
	ctx := context.Background()

	// when
	_, removeErr := service.AcceptEvent(ctx, editModeEvent("apply-ea-remove", "apply-ea-app", "apply-ea-owner",
		map[string]interface{}{"changeType": "component_removed", "entityType": "component", "entityId": "apply-eb-comp"},
		map[string]interface{}{"changeType": "component_group_removed", "entityType": "component_group", "entityId": "apply-eb-app-group"},
	), submitter)
	_, reorderErr := service.AcceptEvent(ctx, editModeEvent("apply-ea-reorder", "apply-ea-app", "apply-ea-owner",
		map[string]interface{}{"changeType": "component_reordered", "entityType": "component", "entityId": "apply-eb-comp", "index": 5},
	), submitter)
	_, collideErr := service.AcceptEvent(ctx, editModeEvent("apply-ea-collide", "apply-ea-app", "apply-ea-owner",
		map[string]interface{}{"changeType": "component_added", "entityType": "component", "entityId": "apply-eb-comp", "data": map[string]interface{}{
			"id": "apply-eb-comp", "componentGroupId": "apply-ea-app-group", "applicationId": "apply-ea-app", "name": "Mine", "index": 0,
			"data": map[string]interface{}{"title": "hijacked"},
		}},
	), submitter)
	_, foreignGroupErr := service.AcceptEvent(ctx, editModeEvent("apply-ea-foreign-group", "apply-ea-app", "apply-ea-owner",
		map[string]interface{}{"changeType": "component_added", "entityType": "component", "entityId": "apply-ea-new", "data": map[string]interface{}{
			"id": "apply-ea-new", "componentGroupId": "apply-eb-app-group", "applicationId": "apply-ea-app", "name": "New", "index": 0,
		}},
	), submitter)

	// then
	assert.NoError(t, removeErr, "removing an entity this app doesn't have is a no-op")
	assert.ErrorIs(t, reorderErr, ErrUnappliable)
	assert.ErrorIs(t, collideErr, ErrUnappliable)
	assert.ErrorIs(t, foreignGroupErr, ErrUnappliable)
	comp, err := appRepo.GetComponentByID("apply-eb-comp")
	require.NoError(t, err)
	assert.Equal(t, "apply-eb-app", comp.ApplicationID)
	assert.Equal(t, "C", comp.Name)
	assert.Equal(t, 0, comp.Index)
	assert.Equal(t, "original", comp.Data["title"])
	_, err = appRepo.GetComponentGroupByID("apply-eb-app-group")
	assert.NoError(t, err)
	_, err = appRepo.GetComponentByID("apply-ea-new")
	assert.ErrorIs(t, err, application.ErrNotFound)
}

func TestAcceptEvent_EditModeBatchWithOneUnappliableChange_ShouldRollBackWholeBatch(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-batch-bad-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	_, err := service.AcceptEvent(context.Background(), editModeEvent(prefix+"evt", prefix+"app", prefix+"owner",
		map[string]interface{}{"changeType": "component_group_added", "entityType": "component_group", "entityId": prefix + "g", "data": map[string]interface{}{
			"id": prefix + "g", "applicationId": prefix + "app", "name": "New group", "index": 0,
		}},
		map[string]interface{}{"changeType": "component_data_changed", "entityType": "component", "entityId": "no-such-component",
			"changedFields": map[string]interface{}{"title": map[string]interface{}{"newValue": "x"}}},
	), &user.User{PublicKey: prefix + "owner"})

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	_, getErr := appRepo.GetComponentGroupByID(prefix + "g")
	assert.ErrorIs(t, getErr, application.ErrNotFound)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", prefix+"evt"))
}

func TestAcceptEvent_EditModeBatchAddingGroupAndComponent_ShouldApplyBoth(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-batch-ok-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	stored, err := service.AcceptEvent(context.Background(), editModeEvent(prefix+"evt", prefix+"app", prefix+"owner",
		map[string]interface{}{"changeType": "component_group_added", "entityType": "component_group", "entityId": prefix + "g", "data": map[string]interface{}{
			"id": prefix + "g", "applicationId": prefix + "app", "name": "New group", "index": 0,
		}},
		map[string]interface{}{"changeType": "component_added", "entityType": "component", "entityId": prefix + "c", "data": map[string]interface{}{
			"id": prefix + "c", "componentGroupId": prefix + "g", "applicationId": prefix + "app", "name": "Chat", "index": 0, "data": nil,
		}},
	), &user.User{PublicKey: prefix + "owner"})

	// then
	require.NoError(t, err)
	comp, err := appRepo.GetComponentByID(prefix + "c")
	require.NoError(t, err)
	assert.Equal(t, prefix+"g", comp.ComponentGroupID)
	assert.Equal(t, stored.SequenceNumber, lastSequence(t, db, prefix+"app"))
}

func TestAcceptEvent_MemberRoleChangedForNonMember_ShouldReject(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-role-nonmember-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	evt := &Event{
		ID: prefix + "evt", Type: EventTypeMemberRoleChanged, CreatorPublicKey: prefix + "owner", Version: 1, CreatedAt: time.Now().Unix(),
		Data: map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": "stranger", "oldRole": "member", "newRole": "admin"},
	}

	// when
	_, err := service.AcceptEvent(context.Background(), evt, &user.User{PublicKey: prefix + "owner"})

	// then: AuthorizeEvent already rejects non-member targets before apply
	assert.ErrorIs(t, err, ErrUnauthorized)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", evt.ID))
}

func TestAcceptEvent_DeletedApplication_ShouldReject(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-deleted-app-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	require.NoError(t, appRepo.DeleteApplication(prefix+"app"))
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	_, err := service.AcceptEvent(context.Background(), componentDataEvent(prefix+"evt", prefix+"app", prefix+"member", prefix+"comp", "x"), &user.User{PublicKey: prefix + "member"})

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", prefix+"evt"))
}

func TestProduceEvent_ApplyFails_ShouldReturnErrorWithoutPersisting(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-produce-fail-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	evt := &Event{
		ID: prefix + "evt", Type: EventTypeMemberRoleChanged, CreatorPublicKey: prefix + "owner", Version: 1,
		Data: map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": "stranger", "oldRole": "member", "newRole": "admin"},
	}

	// when
	_, err := service.ProduceEvent(context.Background(), evt)

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", evt.ID))
}

func TestAcceptEvent_DuplicateID_ShouldReturnStoredEventWithoutReapplying(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-dup-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	broadcaster := &countingBroadcaster{}
	service := NewEventService(NewEventRepository(db), appRepo, broadcaster, nil)
	submitter := &user.User{PublicKey: prefix + "member"}
	first, err := service.AcceptEvent(context.Background(), componentDataEvent(prefix+"evt", prefix+"app", prefix+"member", prefix+"comp", "first"), submitter)
	require.NoError(t, err)

	// when
	again, err := service.AcceptEvent(context.Background(), componentDataEvent(prefix+"evt", prefix+"app", prefix+"member", prefix+"comp", "second"), submitter)

	// then
	require.NoError(t, err)
	assert.Equal(t, first.SequenceNumber, again.SequenceNumber)
	assert.Equal(t, first.CreatedAt, again.CreatedAt)
	assert.Equal(t, 1, countEvents(t, db, "id = $1", prefix+"evt"))
	assert.Contains(t, componentData(t, db, prefix+"comp"), "first")
	assert.NotContains(t, componentData(t, db, prefix+"comp"), "second")
	assert.Equal(t, int32(1), broadcaster.app.Load())
}

func TestAcceptEvent_DeletesOfMissingEntities_ShouldBeAcceptedNoOps(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-missing-delete-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	submitter := &user.User{PublicKey: prefix + "owner"}
	removal := &Event{
		ID: prefix + "member-removed", Type: EventTypeMemberRemoved, CreatorPublicKey: prefix + "owner", Version: 1, CreatedAt: time.Now().Unix(),
		Data: map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": "never-a-member"},
	}

	// when: account deletion produces member_removed, AcceptEvent's authorizer rejects non-members first
	_, memberErr := service.ProduceEvent(context.Background(), removal)
	_, editErr := service.AcceptEvent(context.Background(), editModeEvent(prefix+"edit", prefix+"app", prefix+"owner",
		map[string]interface{}{"changeType": "component_removed", "entityType": "component", "entityId": "gone"},
		map[string]interface{}{"changeType": "component_group_removed", "entityType": "component_group", "entityId": "gone-group"},
	), submitter)

	// then
	assert.NoError(t, memberErr)
	assert.NoError(t, editErr)
	assert.Equal(t, 2, countEvents(t, db, "application_id = $1", prefix+"app"))
}

func TestAcceptEvent_ConcurrentWriters_ShouldGetDistinctContiguousSequences(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-concurrent-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	const writers = 20

	// when
	var wg sync.WaitGroup
	seqs := make([]int64, writers)
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			evt := componentDataEvent(fmt.Sprintf("%sevt-%d", prefix, i), prefix+"app", prefix+"member", prefix+"comp", fmt.Sprint(i))
			stored, err := service.AcceptEvent(context.Background(), evt, &user.User{PublicKey: prefix + "member"})
			errs[i] = err
			if err == nil {
				seqs[i] = stored.SequenceNumber
			}
		}(i)
	}
	wg.Wait()

	// then
	for _, err := range errs {
		require.NoError(t, err)
	}
	sort.Slice(seqs, func(a, b int) bool { return seqs[a] < seqs[b] })
	base := seqs[0]
	for i, seq := range seqs {
		assert.Equal(t, base+int64(i), seq)
	}
	assert.Equal(t, seqs[writers-1], lastSequence(t, db, prefix+"app"))
}

// The reminder scheduler holds a reminder row lock while it calls
// ProduceEvent. A writer that holds the app lock and cascades into that row
// must not leave them waiting on each other forever.
func TestProduceEvent_SchedulerHoldingReminderRowLock_ShouldNotDeadlock(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-deadlock-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	_, err := db.Exec(`INSERT INTO reminder (rule_id, offset_index, application_id, component_id, target_key, tz, offset_spec, anchor_at, due_at, fire_at, rev)
		VALUES ($1, 0, $2, $3, 'k', 'UTC', 'PT0S', 0, 0, 0, 1)`, prefix+"rule", prefix+"app", prefix+"comp")
	require.NoError(t, err)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	ctx := context.Background()

	scheduler, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer scheduler.Rollback()
	_, err = scheduler.Exec(`SELECT 1 FROM reminder WHERE rule_id = $1 FOR UPDATE`, prefix+"rule")
	require.NoError(t, err)

	removeDone := make(chan error, 1)
	go func() {
		_, err := service.AcceptEvent(ctx, editModeEvent(prefix+"remove", prefix+"app", prefix+"owner",
			map[string]interface{}{"changeType": "component_removed", "entityType": "component", "entityId": prefix + "comp"},
		), &user.User{PublicKey: prefix + "owner"})
		removeDone <- err
	}()
	require.Eventually(t, func() bool {
		var waiting int
		_ = db.QueryRow(`SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE '%DELETE FROM components%'`).Scan(&waiting)
		return waiting > 0
	}, 5*time.Second, 20*time.Millisecond, "edit-mode removal should be blocked on the scheduler's reminder row")

	// when
	fireDone := make(chan error, 1)
	go func() {
		_, err := service.ProduceEvent(ctx, &Event{
			ID: prefix + "fired", Type: EventTypeReminderFired, CreatorPublicKey: "space", Version: 1, ApplicationID: prefix + "app",
			Data: map[string]interface{}{"version": 1, "applicationId": prefix + "app", "componentId": prefix + "comp", "targetKey": "k",
				"ruleId": prefix + "rule", "occurrenceAt": 0, "kind": "due", "offset": "PT0S", "itemTitle": "t"},
		})
		fireDone <- err
	}()

	// then
	select {
	case <-fireDone:
	case <-time.After(15 * time.Second):
		t.Fatal("ProduceEvent never returned: the app lock and the scheduler's reminder row lock deadlocked")
	}
	require.NoError(t, scheduler.Rollback())
	select {
	case <-removeDone:
	case <-time.After(15 * time.Second):
		t.Fatal("edit-mode removal never finished after the scheduler released its row")
	}
}

func TestAcceptEvent_RetriedSelfRemoval_ShouldReturnStoredEvent(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-retry-leave-"
	appRepo := seedRoleApp(t, db, prefix)
	broadcaster := &countingBroadcaster{}
	service := NewEventService(NewEventRepository(db), appRepo, broadcaster, nil)
	submitter := &user.User{PublicKey: prefix + "member"}
	leave := func() *Event {
		return &Event{
			ID: prefix + "evt", Type: EventTypeMemberRemoved, CreatorPublicKey: prefix + "member", Version: 1, CreatedAt: time.Now().Unix(),
			Data: map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": prefix + "member"},
		}
	}
	first, err := service.AcceptEvent(context.Background(), leave(), submitter)
	require.NoError(t, err)

	// when
	again, err := service.AcceptEvent(context.Background(), leave(), submitter)

	// then
	require.NoError(t, err)
	assert.Equal(t, first.SequenceNumber, again.SequenceNumber)
	assert.Equal(t, 1, countEvents(t, db, "id = $1", prefix+"evt"))
	assert.Equal(t, int32(1), broadcaster.app.Load())
}

func TestAcceptEvent_RetriedApplicationDeleted_ShouldReturnStoredEvent(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-retry-delete-"
	appRepo := seedRoleApp(t, db, prefix)
	broadcaster := &countingBroadcaster{}
	service := NewEventService(NewEventRepository(db), appRepo, broadcaster, nil)
	submitter := &user.User{PublicKey: prefix + "owner"}
	deletion := func() *Event {
		return &Event{
			ID: prefix + "evt", Type: EventTypeApplicationDeleted, CreatorPublicKey: prefix + "owner", Version: 1, CreatedAt: time.Now().Unix(),
			Data: map[string]interface{}{"applicationId": prefix + "app", "deletedAt": time.Now().UnixMilli()},
		}
	}
	first, err := service.AcceptEvent(context.Background(), deletion(), submitter)
	require.NoError(t, err)

	// when
	again, err := service.AcceptEvent(context.Background(), deletion(), submitter)

	// then
	require.NoError(t, err)
	assert.Equal(t, first.SequenceNumber, again.SequenceNumber)
	assert.Equal(t, 1, countEvents(t, db, "id = $1", prefix+"evt"))
	assert.Equal(t, int32(1), broadcaster.app.Load())
}

func TestProduceEvent_SoftDeletedApplication_ShouldRejectWithoutPersisting(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-produce-deleted-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	require.NoError(t, appRepo.DeleteApplication(prefix+"app"))
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	evt := componentDataEvent(prefix+"evt", prefix+"app", prefix+"owner", prefix+"comp", "x")
	evt.ApplicationID = prefix + "app"

	// when
	_, err := service.ProduceEvent(context.Background(), evt)

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", evt.ID))
	assert.Contains(t, componentData(t, db, prefix+"comp"), "original")
}

func TestAcceptEvent_ApplicationNameWithNulByte_ShouldRejectAsUnappliable(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-nul-name-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	evt := &Event{
		ID: prefix + "evt", Type: EventTypeApplicationDataChanged, CreatorPublicKey: prefix + "owner", Version: 1,
		Data: map[string]interface{}{"applicationId": prefix + "app", "name": "bad\x00name"},
	}

	// when
	_, err := service.AcceptEvent(context.Background(), evt, &user.User{PublicKey: prefix + "owner"})

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", evt.ID))
}

type notNullViolatingReminderStore struct{ db *sql.DB }

func (s notNullViolatingReminderStore) ApplyRuleChange(ctx context.Context, data *ReminderChangedData) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO reminder (rule_id) VALUES ($1)`, data.ID)
	return err
}

func TestProduceEvent_ConstraintViolationDuringExecute_ShouldRejectAsUnappliable(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-23502-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	service.SetReminderStore(notNullViolatingReminderStore{db: db})
	data := reminderChangedEventData()
	data["id"] = prefix + "rule"
	data["applicationId"] = prefix + "app"
	data["offsets"] = []interface{}{"PT0S"}
	evt := &Event{ID: prefix + "evt", Type: EventTypeReminderChanged, CreatorPublicKey: prefix + "owner", Version: 1, Data: data}

	// when
	_, err := service.ProduceEvent(context.Background(), evt)

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Equal(t, 0, countEvents(t, db, "id = $1", evt.ID))
}

func TestAcceptEvent_EditModeComponentAddedWithOtherGroup_ShouldMoveComponent(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-move-group-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	require.NoError(t, appRepo.CreateComponentGroup(&application.ComponentGroup{ID: prefix + "group-2", ApplicationID: prefix + "app", Name: "G2", Index: 1}))
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	_, err := service.AcceptEvent(context.Background(), editModeEvent(prefix+"evt", prefix+"app", prefix+"owner",
		map[string]interface{}{"changeType": "component_added", "entityType": "component", "entityId": prefix + "comp", "data": map[string]interface{}{
			"id": prefix + "comp", "componentGroupId": prefix + "group-2", "applicationId": prefix + "app", "name": "C", "index": 0,
		}},
	), &user.User{PublicKey: prefix + "owner"})

	// then
	require.NoError(t, err)
	comp, err := appRepo.GetComponentByID(prefix + "comp")
	require.NoError(t, err)
	assert.Equal(t, prefix+"group-2", comp.ComponentGroupID)
}

func TestAcceptEvent_ReusedIDForOtherApp_ShouldRejectWithoutTouchingIt(t *testing.T) {
	// given
	db := connectApply(t)
	appRepo := seedRoleApp(t, db, "apply-reuse-a-")
	seedRoleApp(t, db, "apply-reuse-b-")
	seedComponent(t, appRepo, "apply-reuse-a-app", "apply-reuse-a-comp")
	seedComponent(t, appRepo, "apply-reuse-b-app", "apply-reuse-b-comp")
	creator := "apply-reuse-a-member"
	require.NoError(t, appRepo.CreateMember(&application.Member{ID: "apply-reuse-b-extra-id", ApplicationID: "apply-reuse-b-app", Role: application.MemberRoleMember, PublicKey: creator}))
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	submitter := &user.User{PublicKey: creator}
	ctx := context.Background()
	_, err := service.AcceptEvent(ctx, componentDataEvent("apply-reuse-evt", "apply-reuse-a-app", creator, "apply-reuse-a-comp", "first"), submitter)
	require.NoError(t, err)

	// when
	_, err = service.AcceptEvent(ctx, componentDataEvent("apply-reuse-evt", "apply-reuse-b-app", creator, "apply-reuse-b-comp", "second"), submitter)

	// then
	assert.ErrorIs(t, err, ErrUnappliable)
	assert.Contains(t, componentData(t, db, "apply-reuse-b-comp"), "original")
}

func TestAcceptEvent_ComponentGroupChangedWithOnlyName_ShouldKeepIndex(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-group-name-"
	appRepo := seedRoleApp(t, db, prefix)
	require.NoError(t, appRepo.CreateComponentGroup(&application.ComponentGroup{ID: prefix + "group", ApplicationID: prefix + "app", Name: "Old", Index: 3}))
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)

	// when
	_, err := service.AcceptEvent(context.Background(), editModeEvent(prefix+"evt", prefix+"app", prefix+"owner",
		map[string]interface{}{"changeType": "component_group_changed", "entityType": "component_group", "entityId": prefix + "group", "data": map[string]interface{}{"name": "New"}},
	), &user.User{PublicKey: prefix + "owner"})

	// then
	require.NoError(t, err)
	group, err := appRepo.GetComponentGroupByID(prefix + "group")
	require.NoError(t, err)
	assert.Equal(t, "New", group.Name)
	assert.Equal(t, 3, group.Index)
}

func TestAcceptEvent_ForgedCreatorPublicKey_ShouldStoreSubmitterAsCreator(t *testing.T) {
	// given
	db := connectApply(t)
	prefix := "apply-forged-creator-"
	appRepo := seedRoleApp(t, db, prefix)
	seedComponent(t, appRepo, prefix+"app", prefix+"comp")
	repo := NewEventRepository(db)
	service := NewEventService(repo, appRepo, nil, nil)

	// when
	accepted, err := service.AcceptEvent(context.Background(), componentDataEvent(prefix+"evt", prefix+"app", prefix+"owner", prefix+"comp", "x"), &user.User{PublicKey: prefix + "member"})

	// then
	require.NoError(t, err)
	assert.Equal(t, prefix+"member", accepted.CreatorPublicKey)
	stored, err := repo.GetByID(prefix + "evt")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, prefix+"member", stored.CreatorPublicKey)
}
