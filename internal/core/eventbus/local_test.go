package eventbus

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func waitFor(t *testing.T, check func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestLocalBusPubSub(t *testing.T) {
	bus := NewLocal()
	var count int64

	bus.Subscribe("test.topic", func(_ context.Context, ev Event) {
		atomic.AddInt64(&count, 1)
		assert.Equal(t, "hello", ev.Payload)
	})

	bus.Publish(context.Background(), Event{Topic: "test.topic", Payload: "hello"})
	waitFor(t, func() bool { return atomic.LoadInt64(&count) == 1 }, time.Second)
}

func TestLocalBusUnsubscribe(t *testing.T) {
	bus := NewLocal()
	var count int64

	unsub := bus.Subscribe("test", func(_ context.Context, ev Event) {
		atomic.AddInt64(&count, 1)
	})

	bus.Publish(context.Background(), Event{Topic: "test", Payload: nil})
	waitFor(t, func() bool { return atomic.LoadInt64(&count) == 1 }, time.Second)

	unsub()
	bus.Publish(context.Background(), Event{Topic: "test", Payload: nil})
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(1), atomic.LoadInt64(&count))
}

func TestLocalBusMultipleSubscribers(t *testing.T) {
	bus := NewLocal()
	var count int64

	bus.Subscribe("test", func(_ context.Context, ev Event) {
		atomic.AddInt64(&count, 1)
	})
	bus.Subscribe("test", func(_ context.Context, ev Event) {
		atomic.AddInt64(&count, 10)
	})

	bus.Publish(context.Background(), Event{Topic: "test", Payload: nil})
	waitFor(t, func() bool { return atomic.LoadInt64(&count) == 11 }, time.Second)
}

func TestLocalBusPanicRecovery(t *testing.T) {
	bus := NewLocal()
	var count int64

	bus.Subscribe("test", func(_ context.Context, ev Event) {
		panic("test panic")
	})
	bus.Subscribe("test", func(_ context.Context, ev Event) {
		atomic.AddInt64(&count, 1)
	})

	bus.Publish(context.Background(), Event{Topic: "test", Payload: nil})
	waitFor(t, func() bool { return atomic.LoadInt64(&count) == 1 }, time.Second)
}
