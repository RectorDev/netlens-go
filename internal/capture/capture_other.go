//go:build !windows

package capture

import (
	"context"
	"fmt"
)

type unsupported struct{}

func New(tracker *Tracker) (Service, error) { return &unsupported{}, nil }
func (u *unsupported) Run(context.Context) error {
	return fmt.Errorf("transparent capture is Windows-only in NetLens v0.1")
}
func (u *unsupported) Close() error { return nil }
