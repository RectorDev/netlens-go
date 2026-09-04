package capture

import (
	"context"
	"sync"
)

type ProcInfo struct {
	PID  uint32
	Name string
	Path string
}

type Tracker struct {
	mu sync.RWMutex
	m  map[[2]uint16]ProcInfo // local client source port + remote destination port
}

func NewTracker() *Tracker { return &Tracker{m: make(map[[2]uint16]ProcInfo)} }
func (t *Tracker) Put(localPort, remotePort uint16, p ProcInfo) {
	t.mu.Lock()
	t.m[[2]uint16{localPort, remotePort}] = p
	t.mu.Unlock()
}
func (t *Tracker) Delete(localPort, remotePort uint16) {
	t.mu.Lock()
	delete(t.m, [2]uint16{localPort, remotePort})
	t.mu.Unlock()
}
func (t *Tracker) Get(localPort, remotePort uint16) ProcInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.m[[2]uint16{localPort, remotePort}]
}

type Service interface {
	Run(context.Context) error
	Close() error
}
