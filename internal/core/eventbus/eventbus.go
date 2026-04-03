package eventbus

import (
	"context"
	"encoding/json"
)

// Event represents a domain event published through the bus.
type Event struct {
	Topic   string
	Payload any
}

// Handler processes an event. Handlers should not panic; the bus recovers panics but logs them.
type Handler func(ctx context.Context, event Event)

// EventBus is the core abstraction for event-driven communication.
// P1 uses a local in-memory implementation; P2 can swap in Redis Pub/Sub
// by implementing the same interface with serialized payloads.
type EventBus interface {
	Publish(ctx context.Context, event Event)
	Subscribe(topic string, handler Handler) (unsubscribe func())
}

// MarshalPayload serializes the event payload to JSON bytes.
// This creates a serialization boundary so the same code works with Redis Pub/Sub.
func MarshalPayload(payload any) ([]byte, error) {
	return json.Marshal(payload)
}

// UnmarshalPayload deserializes JSON bytes into the target type.
func UnmarshalPayload(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
