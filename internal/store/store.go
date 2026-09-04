package store

import (
	"sync"
	"sync/atomic"

	"netlens/internal/model"
)

type Store struct {
	mu        sync.RWMutex
	flows     []*model.Flow
	maxFlows  int
	nextID    atomic.Uint64
	recording atomic.Bool
}

func New(maxFlows int) *Store {
	if maxFlows <= 0 {
		maxFlows = 5000
	}
	s := &Store{maxFlows: maxFlows}
	s.recording.Store(true)
	return s
}

func (s *Store) NextID() uint64 { return s.nextID.Add(1) }

func (s *Store) Add(f *model.Flow) {
	if f == nil || !s.recording.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append([]*model.Flow{f}, s.flows...)
	if len(s.flows) > s.maxFlows {
		s.flows = s.flows[:s.maxFlows]
	}
}

func (s *Store) List(limit int) []*model.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.flows) {
		limit = len(s.flows)
	}
	out := make([]*model.Flow, limit)
	copy(out, s.flows[:limit])
	return out
}

func (s *Store) Get(id uint64) (*model.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.flows {
		if f.ID == id {
			return f, true
		}
	}
	return nil, false
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = nil
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.flows)
}

func (s *Store) Recording() bool     { return s.recording.Load() }
func (s *Store) SetRecording(v bool) { s.recording.Store(v) }
func (s *Store) MaxFlows() int       { return s.maxFlows }
