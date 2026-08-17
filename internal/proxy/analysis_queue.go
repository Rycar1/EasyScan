package proxy

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/example/easyscan/internal/engine"
	"github.com/example/easyscan/internal/model"
)

// defaultPassiveAnalysisQueueCapacity bounds the amount of captured response
// data retained while passive analysis is slower than proxy forwarding. With
// the default one-megabyte capture limit, 512 jobs is also a clear upper bound
// on the queue's worst-case retained response bodies.
const defaultPassiveAnalysisQueueCapacity = 512

type analysisEnqueueResult uint8

const (
	analysisQueueInactive analysisEnqueueResult = iota
	analysisQueued
	analysisQueueFull
	analysisQueueStopped
)

// passiveAnalysisQueue deliberately uses one consumer. Engine analysis also
// updates a single SQLite snapshot, so additional workers would add lock
// contention without improving the proxy's forwarding latency.
type passiveAnalysisQueue struct {
	engine   *engine.Engine
	capacity int

	mu       sync.RWMutex
	jobs     chan model.Transaction
	done     chan struct{}
	running  bool
	stopping bool
	managed  bool
	dropped  atomic.Uint64
}

func newPassiveAnalysisQueue(e *engine.Engine, capacity int) *passiveAnalysisQueue {
	if capacity <= 0 {
		capacity = defaultPassiveAnalysisQueueCapacity
	}
	return &passiveAnalysisQueue{engine: e, capacity: capacity}
}

// start begins a new queue lifecycle. A Server normally owns exactly one
// lifecycle through Serve, but allowing a completed Server to be served again
// keeps the queue state self-contained and avoids a permanently closed channel.
func (q *passiveAnalysisQueue) start() bool {
	if q == nil || q.engine == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.running || q.stopping {
		return false
	}
	q.jobs = make(chan model.Transaction, q.capacity)
	q.done = make(chan struct{})
	q.running = true
	q.managed = true
	q.dropped.Store(0)
	go q.consume(q.jobs, q.done)
	return true
}

// trySubmit never waits for queue space. Dropping the newest analysis job on
// saturation preserves already queued observations and, most importantly,
// never turns a slow fingerprint/database pass into proxy backpressure.
func (q *passiveAnalysisQueue) trySubmit(transaction model.Transaction) analysisEnqueueResult {
	if q == nil {
		return analysisQueueInactive
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if !q.running {
		if q.managed {
			return analysisQueueStopped
		}
		return analysisQueueInactive
	}
	q.engine.MarkPassiveRequestQueued()
	select {
	case q.jobs <- transaction:
		return analysisQueued
	default:
		q.engine.MarkPassiveRequestDequeued()
		q.dropped.Add(1)
		return analysisQueueFull
	}
}

// stop closes admission first, then drains every job that was accepted before
// waiting for the sole consumer to exit. A producer racing with stop is safe:
// trySubmit holds the read lock while sending, so the channel is never closed
// underneath a send.
func (q *passiveAnalysisQueue) stop() {
	if q == nil {
		return
	}
	q.mu.Lock()
	if !q.running {
		q.mu.Unlock()
		return
	}
	q.running = false
	q.stopping = true
	jobs, done := q.jobs, q.done
	close(jobs)
	q.mu.Unlock()

	<-done

	q.mu.Lock()
	if q.done == done {
		q.jobs = nil
		q.done = nil
		q.stopping = false
	}
	q.mu.Unlock()
}

func (q *passiveAnalysisQueue) consume(jobs <-chan model.Transaction, done chan<- struct{}) {
	defer close(done)
	for transaction := range jobs {
		q.engine.MarkPassiveRequestDequeued()
		q.analyze(transaction)
		q.reportDropped()
	}
	q.reportDropped()
}

func (q *passiveAnalysisQueue) analyze(transaction model.Transaction) {
	// Keep a malformed rule or third-party matcher panic from permanently
	// killing the only consumer and silently filling the bounded queue.
	defer func() {
		if recovered := recover(); recovered != nil {
			q.engine.Log("error", "proxy", fmt.Sprintf("被动分析任务异常：%v", recovered))
		}
	}()
	q.engine.Analyze(transaction)
}

// Queue saturation is reported by the consumer rather than the forwarding
// goroutine, so even diagnostic logging cannot delay a browser response.
// Rejected jobs release their temporary queue counter reservation immediately.
func (q *passiveAnalysisQueue) reportDropped() {
	if dropped := q.dropped.Swap(0); dropped > 0 {
		q.engine.Log("warn", "proxy", fmt.Sprintf("被动分析队列已满，已跳过 %d 个最新响应", dropped))
	}
}
