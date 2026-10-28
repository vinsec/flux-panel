package control

import (
	"context"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"time"
)

// The network process can request typed operations, not commands or rulesets.
type ManagerAPI interface {
	Info() map[string]any
	RequireCreditPolicy() error
	Report() (engine.Report, error)
	Acknowledge(engine.Acknowledgement) error
	InstallGrants([]engine.LeaseGrant) error
	CreditReady(string) bool
	Collect(time.Duration) (int, error)
	Submit(engine.Batch) (engine.Job, error)
	Job(string) (engine.Job, error)
	Page(string, int, *uint64) (engine.Page, error)
	Apply(engine.Spec) error
	Change(string, int64, bool, bool) error
	Rules() map[string]engine.Spec
	RuntimeStatus(string) map[string]any
	RuntimeStatuses([]string) map[string]map[string]any
	Diagnostics(context.Context, string, bool) (map[string]any, error)
	ReturnPathDiagnostics(context.Context, string, bool, engine.ReturnPathQuery) (map[string]any, error)
	StartJobs(context.Context)
	StartRuntime(context.Context) error
	RefreshRuntime(context.Context) error
	EnforceExpiration() error
	Connected(bool)
	TransportAcknowledged()
	CompleteMaintenance(engine.Acknowledgement) error
	ConfigureResolver([]string)
}
