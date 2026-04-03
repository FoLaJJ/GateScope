package eventbus

import (
	"context"
	"runtime/debug"
	"sync"

	"github.com/AutoScan/agentscan/internal/core/logger"
	"go.uber.org/zap"
)

const defaultWorkerPoolSize = 64
const defaultBufferSize = 256

type localBus struct {
	mu      sync.RWMutex
	subs    map[string]map[uint64]Handler
	seq     uint64
	workCh  chan workItem
	closeCh chan struct{}
}

type workItem struct {
	ctx     context.Context
	handler Handler
	event   Event
}

// NewLocal creates a local in-memory EventBus with async dispatch.
// Handlers run in a goroutine pool to prevent blocking the publisher.
func NewLocal() EventBus {
	b := &localBus{
		subs:    make(map[string]map[uint64]Handler),
		workCh:  make(chan workItem, defaultBufferSize),
		closeCh: make(chan struct{}),
	}
	for range defaultWorkerPoolSize {
		go b.worker()
	}
	return b
}

func (b *localBus) worker() {
	log := logger.Named("eventbus")
	for {
		select {
		case w := <-b.workCh:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Error("handler panic recovered",
							zap.String("topic", w.event.Topic),
							zap.Any("panic", r),
							zap.String("stack", string(debug.Stack())),
						)
					}
				}()
				w.handler(w.ctx, w.event)
			}()
		case <-b.closeCh:
			return
		}
	}
}

func (b *localBus) Publish(ctx context.Context, event Event) {
	b.mu.RLock()
	handlers := make([]Handler, 0, len(b.subs[event.Topic]))
	for _, h := range b.subs[event.Topic] {
		handlers = append(handlers, h)
	}
	b.mu.RUnlock()

	for _, h := range handlers {
		select {
		case b.workCh <- workItem{ctx: ctx, handler: h, event: event}:
		default:
			logger.Named("eventbus").Warn("dispatch buffer full, dropping event",
				zap.String("topic", event.Topic),
			)
		}
	}
}

func (b *localBus) Subscribe(topic string, handler Handler) func() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.subs[topic] == nil {
		b.subs[topic] = make(map[uint64]Handler)
	}

	b.seq++
	id := b.seq
	b.subs[topic][id] = handler

	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subs[topic], id)
	}
}

// Close shuts down the worker pool. Call on application shutdown.
func (b *localBus) Close() {
	close(b.closeCh)
}
