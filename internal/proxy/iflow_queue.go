package proxy

import (
	"context"
	"fmt"
	"sync"
)

type iflowQueueManager struct {
	mu     sync.Mutex
	queues map[uint]*iflowKeyQueue
}

type iflowKeyQueue struct {
	mu      sync.Mutex
	running bool
	waiters []*iflowWaiter
}

type iflowWaiter struct {
	ready   chan struct{}
	started bool
}

type iflowQueueSlot struct {
	queue *iflowKeyQueue
}

func newIFlowQueueManager() *iflowQueueManager {
	return &iflowQueueManager{
		queues: make(map[uint]*iflowKeyQueue),
	}
}

func (m *iflowQueueManager) Acquire(ctx context.Context, keyID uint) (*iflowQueueSlot, error) {
	if ctx == nil {
		return nil, fmt.Errorf("iflow queue: context is nil")
	}

	q := m.getQueue(keyID)
	w := &iflowWaiter{ready: make(chan struct{})}

	q.mu.Lock()
	q.waiters = append(q.waiters, w)
	q.startNextLocked()
	q.mu.Unlock()

	select {
	case <-w.ready:
		return &iflowQueueSlot{queue: q}, nil
	case <-ctx.Done():
		// Attempt to cancel. If it already started, we must return a slot so the caller can release.
		q.mu.Lock()
		started := w.started
		if !started {
			q.removeWaiterLocked(w)
			q.startNextLocked()
		}
		q.mu.Unlock()

		if started {
			return &iflowQueueSlot{queue: q}, nil
		}
		return nil, ctx.Err()
	}
}

func (m *iflowQueueManager) getQueue(keyID uint) *iflowKeyQueue {
	m.mu.Lock()
	defer m.mu.Unlock()

	q, ok := m.queues[keyID]
	if !ok {
		q = &iflowKeyQueue{}
		m.queues[keyID] = q
	}
	return q
}

func (q *iflowKeyQueue) HasWaiting() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.waiters) > 1
}

func (s *iflowQueueSlot) HasWaiting() bool {
	if s == nil || s.queue == nil {
		return false
	}
	return s.queue.HasWaiting()
}

func (s *iflowQueueSlot) Release() {
	if s == nil || s.queue == nil {
		return
	}

	q := s.queue
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.running {
		return
	}

	q.running = false
	if len(q.waiters) > 0 {
		q.waiters[0] = nil
		q.waiters = q.waiters[1:]
	}
	q.startNextLocked()
}

func (q *iflowKeyQueue) startNextLocked() {
	for !q.running && len(q.waiters) > 0 {
		next := q.waiters[0]
		if next == nil {
			q.waiters = q.waiters[1:]
			continue
		}
		if next.started {
			q.running = true
			return
		}
		q.running = true
		next.started = true
		close(next.ready)
		return
	}
}

func (q *iflowKeyQueue) removeWaiterLocked(w *iflowWaiter) {
	if w == nil {
		return
	}
	for i := range q.waiters {
		if q.waiters[i] == w {
			copy(q.waiters[i:], q.waiters[i+1:])
			q.waiters[len(q.waiters)-1] = nil
			q.waiters = q.waiters[:len(q.waiters)-1]
			return
		}
	}
}
