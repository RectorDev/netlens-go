package intercept

import (
	"sync"
	"sync/atomic"
	"time"

	"netlens/internal/model"
)

type Decision string

const (
	Continue Decision = "continue"
	Drop     Decision = "drop"
)

// Manager coordinates HTTPS request breakpoints between the proxy and UI.
// Interception is opt-in and disabled by default.
type Manager struct {
	enabled atomic.Bool
	nextID  atomic.Uint64

	mu      sync.RWMutex
	pending map[uint64]*entry
	timeout time.Duration
}

type entry struct {
	request  model.PausedRequest
	decision chan Decision
}

func New() *Manager {
	return &Manager{
		pending: make(map[uint64]*entry),
		timeout: 5 * time.Minute,
	}
}

func (m *Manager) Enabled() bool { return m.enabled.Load() }

// SetEnabled enables/disables request breakpoints. Disabling interception
// continues every request currently waiting so client applications are not
// accidentally left hanging.
func (m *Manager) SetEnabled(v bool) {
	m.enabled.Store(v)
	if !v {
		m.ResolveAll(Continue)
	}
}

func (m *Manager) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

func (m *Manager) List() []model.PausedRequest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.PausedRequest, 0, len(m.pending))
	for _, e := range m.pending {
		out = append(out, e.request)
	}
	// Newest first, matching the main capture table.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartedAt.After(out[i].StartedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Pause registers a request and blocks until the user makes a decision,
// interception is disabled, or the safety timeout expires. Timeouts continue
// the request rather than silently breaking client traffic forever.
func (m *Manager) Pause(req model.PausedRequest) Decision {
	if !m.Enabled() {
		return Continue
	}
	if req.ID == 0 {
		req.ID = m.nextID.Add(1)
	}
	if req.StartedAt.IsZero() {
		req.StartedAt = time.Now()
	}
	e := &entry{request: req, decision: make(chan Decision, 1)}
	m.mu.Lock()
	m.pending[req.ID] = e
	m.mu.Unlock()

	timer := time.NewTimer(m.timeout)
	defer timer.Stop()
	var d Decision
	select {
	case d = <-e.decision:
	case <-timer.C:
		d = Continue
	}

	m.mu.Lock()
	delete(m.pending, req.ID)
	m.mu.Unlock()
	return d
}

func (m *Manager) Resolve(id uint64, d Decision) bool {
	if d != Continue && d != Drop {
		return false
	}
	m.mu.RLock()
	e, ok := m.pending[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case e.decision <- d:
		return true
	default:
		return false
	}
}

func (m *Manager) ResolveAll(d Decision) int {
	m.mu.RLock()
	entries := make([]*entry, 0, len(m.pending))
	for _, e := range m.pending {
		entries = append(entries, e)
	}
	m.mu.RUnlock()
	resolved := 0
	for _, e := range entries {
		select {
		case e.decision <- d:
			resolved++
		default:
		}
	}
	return resolved
}
