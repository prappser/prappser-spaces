package event

import (
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/rs/zerolog/log"
)

type EntryKeyFunc func(componentName, key string) bool

func (s *EventService) SetEntryKeys(fn EntryKeyFunc) {
	s.entryKeys = fn
}

// Entries are deleted with an empty-string tombstone; a null comes from an old client
// saving its whole data map, so it is dropped. The event is still stored so the
// ack and cursor stay consistent.
func (s *EventService) dropEntryNullDeletes(event *Event) {
	if s.entryKeys == nil {
		return
	}
	switch event.Type {
	case EventTypeComponentDataChanged:
		id, _ := event.Data["componentId"].(string)
		s.dropFromChange(event.ApplicationID, id, event.Data)
	case EventTypeApplicationAfterEditModeChanged:
		changes, _ := event.Data["changes"].([]interface{})
		for _, raw := range changes {
			change, _ := raw.(map[string]interface{})
			if change["changeType"] == "component_data_changed" {
				id, _ := change["entityId"].(string)
				s.dropFromChange(event.ApplicationID, id, change)
			}
		}
	}
}

func (s *EventService) dropFromChange(appID, componentID string, holder map[string]interface{}) {
	fields, _ := holder["changedFields"].(map[string]interface{})
	if len(fields) == 0 || componentID == "" {
		return
	}
	var comp *application.Component
	for key, raw := range fields {
		change, ok := raw.(map[string]interface{})
		if !ok || change["newValue"] != nil {
			continue
		}
		if comp == nil {
			c, err := s.appRepo.GetComponentByID(componentID)
			if err != nil {
				log.Debug().Err(err).Str("componentId", componentID).Msg("[EVENT] Entry guard component lookup failed")
				return
			}
			if c.ApplicationID != appID {
				return
			}
			comp = c
		}
		if s.entryKeys(comp.Name, key) {
			log.Debug().Str("key", key).Str("componentId", componentID).Str("applicationId", appID).Msg("[EVENT] Dropped null delete of entry key")
			delete(fields, key)
		}
	}
}
