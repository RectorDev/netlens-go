package intercept

import (
	"testing"
	"time"

	"netlens/internal/model"
)

func TestPauseAndContinue(t *testing.T) {
	m := New()
	m.SetEnabled(true)
	done := make(chan Decision, 1)
	go func() {
		done <- m.Pause(model.PausedRequest{Host: "example.com", Method: "GET"})
	}()
	deadline := time.Now().Add(time.Second)
	for m.PendingCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.PendingCount() != 1 {
		t.Fatal("request was not queued")
	}
	items := m.List()
	if len(items) != 1 || items[0].ID == 0 {
		t.Fatalf("unexpected pending list: %#v", items)
	}
	if !m.Resolve(items[0].ID, Continue) {
		t.Fatal("resolve failed")
	}
	select {
	case got := <-done:
		if got != Continue {
			t.Fatalf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("pause did not unblock")
	}
}

func TestDisableContinuesPending(t *testing.T) {
	m := New()
	m.SetEnabled(true)
	done := make(chan Decision, 1)
	go func() { done <- m.Pause(model.PausedRequest{Host: "example.com"}) }()
	deadline := time.Now().Add(time.Second)
	for m.PendingCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	m.SetEnabled(false)
	select {
	case got := <-done:
		if got != Continue {
			t.Fatalf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("disable did not release pending request")
	}
}
