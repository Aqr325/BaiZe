// Package delegation replicates the multi-agent orchestration design of
// hermes-agent (nousresearch/hermes-agent) into BaiZe.
//
// This file is the "智能体角色分工" (role division) seam: a DelegationProvider
// decides HOW one delegate_task becomes a child run — which model, provider,
// endpoint and reasoning effort the child uses, or which agent role it runs as.
// It mirrors agent/delegation_provider.py + agent/delegation_registry.py.
//
// Everything crossing this interface is plain JSON data (no live agent objects),
// so a provider runs unchanged in-process. Fail-closed is the invariant: a
// configured backend that is not registered or reports unavailable returns a
// tool error naming the backend and the fix, and never quietly runs children on
// another route.
package delegation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Route is the resolved route one delegate_task child run takes. Empty fields
// mean "inherit the parent's route" (like an empty delegation config section).
// It mirrors DelegationProvider.route_task's return vocabulary.
type Route struct {
	Model           string `json:"model,omitempty"`
	Provider        string `json:"provider,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`
	APIKey          string `json:"api_key,omitempty"`
	APIMode         string `json:"api_mode,omitempty"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	ServiceTier     string `json:"service_tier,omitempty"`
	// Profile names an agent role; core runs the child as that role. A profile
	// route ignores the other route keys.
	Profile string `json:"profile,omitempty"`
	// Label is short text shown with the child's progress and result.
	Label string `json:"label,omitempty"`
}

// TaskSpec is what route_task receives for one task. It carries the goal,
// context, index and the values the model supplied for this provider's
// task parameters (absent when omitted).
type TaskSpec struct {
	Goal    string         `json:"goal"`
	Context string         `json:"context,omitempty"`
	Index   int            `json:"index,omitempty"`
	Group   string         `json:"group,omitempty"`
	Role    string         `json:"role,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
}

// Config is the "delegation" config section of the active profile, read-only:
// dict copy is the default route, and Backends.<name> is this backend's own
// block. Mirrors the delegation section hermes keeps in config.yaml.
type Config struct {
	// Backend is delegation.backend (normalized; blank means "default").
	Backend string `json:"backend,omitempty"`
	// DefaultRoute is the default route inherited by children with empty routes.
	DefaultRoute Route `json:"route,omitempty"`
	// Backends holds per-backend settings: delegation.backends.<name>.
	Backends map[string]map[string]any `json:"backends,omitempty"`
	// MaxConcurrency bounds how many children run in parallel (0 = default 4).
	MaxConcurrency int `json:"max_concurrency,omitempty"`
	// MaxDepth bounds delegate nesting (0 = default 2).
	MaxDepth int `json:"max_depth,omitempty"`
	// MaxBackground bounds background units (0 = default 2).
	MaxBackground int `json:"max_background,omitempty"`
	// TimeoutSeconds bounds each child's wait (0 = no explicit deadline).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// ChildTimeout returns the per-child wait bound in seconds (0 = none).
func (c Config) ChildTimeout() int { return c.TimeoutSeconds }

// DefaultBackend is the backend name used when delegation.backend is unset.
const DefaultBackend = "default"

// DelegationRouteError refuses a task; the message becomes the delegate_task
// tool error the model reads, so phrase it as an instruction.
type DelegationRouteError struct{ Msg string }

func (e *DelegationRouteError) Error() string { return e.Msg }

func routeErrorf(format string, args ...any) error {
	return &DelegationRouteError{Msg: fmt.Sprintf(format, args...)}
}

// RouteKeys are the keys a route may carry; anything else in a provider's
// answer is ignored. Mirrors ROUTE_KEYS.
var RouteKeys = map[string]bool{
	"model": true, "provider": true, "base_url": true, "api_key": true,
	"api_mode": true, "request_overrides": true, "reasoning_effort": true,
	"service_tier": true, "fallback_providers": true, "profile": true, "label": true,
}

// ReservedTaskParameters are per-task property names core owns. A
// provider-declared parameter with one of these names is refused at schema
// build time. Mirrors RESERVED_TASK_PARAMETERS.
var ReservedTaskParameters = map[string]bool{
	"goal": true, "context": true, "index": true, "output_schema": true,
	"images": true, "group": true, "role": true, "toolsets": true,
	"acp_command": true, "acp_args": true, "provider": true, "model": true,
	"base_url": true, "api_key": true, "api_mode": true,
}

// Provider is the abstract base for a pluggable delegation strategy.
// It mirrors DelegationProvider.
type Provider interface {
	// Name is the delegation.backend value.
	Name() string
	// Summary is one user-facing line for backend pickers; never shown to the model.
	Summary() string
	// RouteKeys lists this backend's own route-entry keys beyond core route fields.
	RouteKeys() []string
	// IsAvailable reports whether this provider can run here. MUST NOT make
	// network calls. False fails delegation closed.
	IsAvailable() bool
	// TaskParameters returns extra per-task JSON-schema properties merged into
	// delegate_task's tasks.items.properties. Deterministic for a given config.
	TaskParameters(cfg Config) map[string]map[string]any
	// RouteTask returns the route for one task. Raise DelegationRouteError to
	// refuse the task.
	RouteTask(task TaskSpec, cfg Config) (Route, error)
}

// Settings returns this backend's own config block: delegation.backends.<name>.
func Settings(cfg Config, name string) map[string]any {
	if m, ok := cfg.Backends[name]; ok {
		return m
	}
	return map[string]any{}
}

// NormalizeBackend lower-cases + trims; blank becomes DefaultBackend.
func NormalizeBackend(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return DefaultBackend
	}
	return s
}

// Registry is the delegation provider registry, populated via Register. It
// mirrors ProviderRegistry in agent/delegation_registry.py.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	order     []string
}

// NewRegistry returns an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}}
}

// Register adds or replaces a provider under its Name (normalized).
func (r *Registry) Register(p Provider) {
	if p == nil {
		return
	}
	name := NormalizeBackend(p.Name())
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[name]; !ok {
		r.order = append(r.order, name)
	}
	r.providers[name] = p
}

// Get returns the registered provider for name (normalized).
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[NormalizeBackend(name)]
	return p, ok
}

// List returns providers ordered: default first, then alphabetical.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Provider, 0, len(names))
	for _, n := range names {
		out = append(out, r.providers[n])
	}
	return out
}

// Global is the process-wide registry (mirrors _registry).
var Global = NewRegistry()

// DefaultProvider is the built-in "default" strategy: every child follows the
// delegation default route (else the parent's route). Mirrors the bundled
// plugins/delegation/default plugin.
type DefaultProvider struct{}

// Name returns "default".
func (DefaultProvider) Name() string { return DefaultBackend }

// Summary returns a one-line picker description.
func (DefaultProvider) Summary() string { return "Follow the delegation default route" }

// RouteKeys returns no extra route keys.
func (DefaultProvider) RouteKeys() []string { return nil }

// IsAvailable always true.
func (DefaultProvider) IsAvailable() bool { return true }

// TaskParameters returns none.
func (DefaultProvider) TaskParameters(Config) map[string]map[string]any { return nil }

// RouteTask returns the config's default route (empty = inherit parent).
func (DefaultProvider) RouteTask(task TaskSpec, cfg Config) (Route, error) {
	return cfg.DefaultRoute, nil
}

func init() {
	Global.Register(DefaultProvider{})
}

// BackendStatus returns (provider, "" ) when backend name can run here, else
// (provider-or-nil, reason); the reason is the user-facing fix. Mirrors
// backend_status.
func BackendStatus(name string) (Provider, string) {
	key := NormalizeBackend(name)
	p, ok := Global.Get(key)
	if !ok || p == nil {
		if key == DefaultBackend {
			return nil, "No default delegation strategy is available: the bundled default provider was not registered. Register it with delegation.Register(DefaultProvider{})."
		}
		return nil, fmt.Sprintf("Delegation backend '%s' is not installed: no registered provider provides it. Register one, or switch back to the default backend.", name)
	}
	if !p.IsAvailable() {
		return p, fmt.Sprintf("Delegation backend '%s' is unavailable here (its provider reports it cannot run). Fix its setup, or switch back to the default backend.", name)
	}
	return p, ""
}

// ActiveProvider is the provider cfg selects; "default" when unset. Raises
// DelegationRouteError naming the backend and the fix when not available.
// Mirrors get_active_provider.
func ActiveProvider(cfg Config) (Provider, error) {
	p, reason := BackendStatus(cfg.Backend)
	if reason != "" || p == nil {
		return nil, routeErrorf("%s No subagent was started.", reason)
	}
	return p, nil
}

// ConfigFromJSON parses a delegation config section from raw JSON.
func ConfigFromJSON(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 {
		return Config{Backend: DefaultBackend}, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("delegation config: %w", err)
	}
	if c.Backend == "" {
		c.Backend = DefaultBackend
	}
	return c, nil
}
