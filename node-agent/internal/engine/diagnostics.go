package engine

import "context"

func (m *Manager) Diagnostics(ctx context.Context, id string, probe bool) (map[string]any, error) {
	return m.ReturnPathDiagnostics(ctx, id, probe, ReturnPathQuery{})
}
