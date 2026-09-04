package store

import (
	"netlens/internal/model"
	"testing"
)

func TestStoreNewestFirstAndLimit(t *testing.T) {
	s := New(2)
	a := &model.Flow{ID: s.NextID(), URL: "https://a.test"}
	b := &model.Flow{ID: s.NextID(), URL: "https://b.test"}
	c := &model.Flow{ID: s.NextID(), URL: "https://c.test"}
	s.Add(a)
	s.Add(b)
	s.Add(c)

	got := s.List(10)
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if got[0].ID != c.ID || got[1].ID != b.ID {
		t.Fatalf("wrong order/eviction: got IDs %d,%d", got[0].ID, got[1].ID)
	}
	if _, ok := s.Get(a.ID); ok {
		t.Fatal("evicted flow still present")
	}
	s.Clear()
	if s.Count() != 0 {
		t.Fatalf("count after clear=%d", s.Count())
	}
}

func TestRecordingPause(t *testing.T) {
	s := New(10)
	s.SetRecording(false)
	s.Add(&model.Flow{ID: s.NextID()})
	if s.Count() != 0 {
		t.Fatalf("paused store recorded flow")
	}
	s.SetRecording(true)
	s.Add(&model.Flow{ID: s.NextID()})
	if s.Count() != 1 {
		t.Fatalf("resumed store count=%d", s.Count())
	}
}
