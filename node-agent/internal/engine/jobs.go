package engine

import (
	"context"
	"fmt"
	"time"
)

type Job struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Hash       string `json:"-"`
	FinishedAt int64  `json:"-"`
}

func (m *Manager) StartJobs(ctx context.Context) {
	m.jobsOnce.Do(func() {
		m.jobs = map[string]Job{}
		m.queue = make(chan Batch, 4)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-m.queue:
					m.jobsMu.Lock()
					job := m.jobs[b.ID]
					job.Status = "running"
					m.jobs[b.ID] = job
					m.jobsMu.Unlock()
					e := m.ApplyBatch(b)
					m.mu.Lock()
					gen := m.state.Generation
					m.mu.Unlock()
					m.jobsMu.Lock()
					job = m.jobs[b.ID]
					job.Status = "succeeded"
					if e != nil {
						job.Status = "failed"
						job.Error = e.Error()
					}
					job.Generation = gen
					job.FinishedAt = time.Now().UnixMilli()
					m.jobs[b.ID] = job
					for id, j := range m.jobs {
						if len(m.jobs) <= 128 {
							break
						}
						if j.FinishedAt != 0 && id != b.ID {
							delete(m.jobs, id)
						}
					}
					m.jobsMu.Unlock()
				}
			}
		}()
	})
}
func (m *Manager) Submit(b Batch) (Job, error) {
	m.StartJobs(context.Background())
	hash := digest(b)
	m.jobsMu.Lock()
	defer m.jobsMu.Unlock()
	if j, ok := m.jobs[b.ID]; ok {
		if j.Hash != hash {
			return j, fmt.Errorf("batch ID payload conflict")
		}
		return j, nil
	}
	if len(b.ID) < 1 || len(b.ID) > 100 || len(b.Specs) > 10000 {
		return Job{}, fmt.Errorf("invalid batch")
	}
	job := Job{ID: b.ID, Status: "queued", Hash: hash}
	m.jobs[b.ID] = job
	select {
	case m.queue <- b:
		return job, nil
	default:
		delete(m.jobs, b.ID)
		return Job{}, fmt.Errorf("batch queue is full; retry")
	}
}
func (m *Manager) Job(id string) (Job, error) {
	m.jobsMu.Lock()
	j, ok := m.jobs[id]
	m.jobsMu.Unlock()
	if ok {
		return j, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.state.Receipts {
		if r.ID == id {
			return Job{ID: id, Status: "succeeded", Generation: r.Generation}, nil
		}
	}
	return Job{ID: id, Status: "unknown"}, nil
}
