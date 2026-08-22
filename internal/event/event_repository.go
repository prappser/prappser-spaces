package event

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type EventRepository struct {
	db *sql.DB
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

func (r *EventRepository) GetNextSequence(applicationID string) (int64, error) {
	var maxSeq int64
	query := `SELECT COALESCE(MAX(sequence_number), 0)
			  FROM events
			  WHERE application_id = $1`

	err := r.db.QueryRow(query, applicationID).Scan(&maxSeq)
	if err != nil {
		return 0, fmt.Errorf("failed to get next sequence: %w", err)
	}

	return maxSeq + 1, nil
}

func (r *EventRepository) Create(event *Event) error {
	if event.CreatedAt == 0 {
		event.CreatedAt = time.Now().Unix()
	}

	// For app-scoped events, try to resolve ApplicationID from data if not set
	if event.ApplicationID == "" && !IsUserScoped(event.Type) {
		appID, ok := event.Data["applicationId"].(string)
		if ok && appID != "" {
			event.ApplicationID = appID
		}
	}

	if event.SequenceNumber == 0 && event.ApplicationID != "" {
		seq, err := r.GetNextSequence(event.ApplicationID)
		if err != nil {
			return fmt.Errorf("failed to get next sequence: %w", err)
		}
		event.SequenceNumber = seq
	}

	dataJSON, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Use nil for user-scoped events (application_id is NULL in DB)
	var appID interface{}
	if event.ApplicationID != "" {
		appID = event.ApplicationID
	}

	var spaceIDVal interface{}
	if event.SpaceID != "" {
		spaceIDVal = event.SpaceID
	}

	query := `INSERT INTO events (id, created_at, application_id, sequence_number, type, creator_public_key, version, data, space_id)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = r.db.Exec(query,
		event.ID,
		event.CreatedAt,
		appID,
		event.SequenceNumber,
		string(event.Type),
		event.CreatorPublicKey,
		event.Version,
		string(dataJSON),
		spaceIDVal,
	)

	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}

	return nil
}

func (r *EventRepository) GetByID(id string) (*Event, error) {
	query := `SELECT id, created_at, application_id, sequence_number, type, creator_public_key, version, data
			  FROM events WHERE id = $1`

	event := &Event{}
	var eventType string
	var dataJSON string
	var appID sql.NullString

	err := r.db.QueryRow(query, id).Scan(
		&event.ID,
		&event.CreatedAt,
		&appID,
		&event.SequenceNumber,
		&eventType,
		&event.CreatorPublicKey,
		&event.Version,
		&dataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query event: %w", err)
	}

	if appID.Valid {
		event.ApplicationID = appID.String
	}

	event.Type = EventType(eventType)

	if err := json.Unmarshal([]byte(dataJSON), &event.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	return event, nil
}

func (r *EventRepository) GetSince(userPublicKey string, sinceEventID string, limit int) ([]*Event, bool, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	var sinceOrdinal int64
	if sinceEventID != "" {
		err := r.db.QueryRow("SELECT ordinal FROM events WHERE id = $1", sinceEventID).Scan(&sinceOrdinal)
		if err != nil && err != sql.ErrNoRows {
			return nil, false, fmt.Errorf("failed to get since event: %w", err)
		}
		// sql.ErrNoRows (pruned cursor) leaves sinceOrdinal at 0, which the query
		// below treats the same as no cursor: a full replay.
	}

	// The cursor key is ordinal, not (created_at, id). created_at is whole seconds
	// (AcceptEvent overwrites it with time.Now().Unix()) and event ids are
	// client-minted UUIDv7, so neither can form a total order over the server's
	// accept sequence; a page boundary landing mid-second used to drop rows.
	// ordinal is a server-assigned BIGSERIAL, so one predicate serves both the
	// app-scoped and user-scoped halves with no risk of disagreeing. See #47.
	query := `(SELECT DISTINCT e.ordinal, e.id, e.created_at, e.application_id, e.sequence_number,
			         e.type, e.creator_public_key, e.version, e.data
			  FROM events e
			  INNER JOIN members m ON e.application_id = m.application_id
			  WHERE m.public_key = $1 AND e.ordinal > $2)
			 UNION ALL
			 (SELECT e.ordinal, e.id, e.created_at, e.application_id, e.sequence_number,
			         e.type, e.creator_public_key, e.version, e.data
			  FROM events e
			  WHERE e.application_id IS NULL AND e.creator_public_key = $1 AND e.ordinal > $2)
			 ORDER BY ordinal ASC
			 LIMIT $3`

	rows, err := r.db.Query(query, userPublicKey, sinceOrdinal, limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var ordinal int64
		event := &Event{}
		var eventType string
		var dataJSON string
		var appID sql.NullString

		err := rows.Scan(
			&ordinal,
			&event.ID,
			&event.CreatedAt,
			&appID,
			&event.SequenceNumber,
			&eventType,
			&event.CreatorPublicKey,
			&event.Version,
			&dataJSON,
		)
		if err != nil {
			return nil, false, fmt.Errorf("failed to scan event: %w", err)
		}

		if appID.Valid {
			event.ApplicationID = appID.String
		}

		event.Type = EventType(eventType)

		if err := json.Unmarshal([]byte(dataJSON), &event.Data); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal event data: %w", err)
		}

		events = append(events, event)

		if len(events) > limit {
			break
		}
	}

	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("error iterating events: %w", err)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}

	return events, hasMore, nil
}

func (r *EventRepository) GetByApplicationID(appID string, limit int) ([]*Event, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, created_at, application_id, sequence_number, type, creator_public_key, version, data
			  FROM events
			  WHERE application_id = $1
			  ORDER BY sequence_number ASC, created_at ASC
			  LIMIT $2`

	rows, err := r.db.Query(query, appID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event := &Event{}
		var eventType string
		var dataJSON string
		var appIDNull sql.NullString

		err := rows.Scan(
			&event.ID,
			&event.CreatedAt,
			&appIDNull,
			&event.SequenceNumber,
			&eventType,
			&event.CreatorPublicKey,
			&event.Version,
			&dataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if appIDNull.Valid {
			event.ApplicationID = appIDNull.String
		}

		event.Type = EventType(eventType)

		if err := json.Unmarshal([]byte(dataJSON), &event.Data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
		}

		events = append(events, event)
	}

	return events, rows.Err()
}

func (r *EventRepository) DeleteOlderThan(timestamp int64) (int64, error) {
	query := `DELETE FROM events WHERE created_at < $1`

	result, err := r.db.Exec(query, timestamp)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old events: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

func (r *EventRepository) GetOldestEventID() (string, error) {
	query := `SELECT id FROM events ORDER BY created_at ASC, id ASC LIMIT 1`

	var id string
	err := r.db.QueryRow(query).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get oldest event ID: %w", err)
	}

	return id, nil
}

func (r *EventRepository) Count() (int64, error) {
	query := `SELECT COUNT(*) FROM events`

	var count int64
	err := r.db.QueryRow(query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	return count, nil
}
