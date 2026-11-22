package server

import (
	"fmt"
	"log"

	"github.com/Autumn-27/baize/agent"
	"github.com/Autumn-27/baize/agent/delegation"
	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// wireDelegation wires the multi-agent collaboration surface into the runtime.
// It mirrors hermes-agent's subagent_lifecycle + delegation wiring:
//
//   - a LifecycleService (state machine + terminal-retention registry + broker)
//     running children through agent.RunSubagentTurn (the real TurnFn);
//   - the delegate_task tool injected into every agent's base list;
//   - the child provider / store / working-dir / proxy the runner needs.
//
// The child provider resolves to the process-wide LLM provider, so a child with
// an empty delegation route inherits the parent's route (the hermes "default"
// backend semantic). Children run task-less: no ExplorationStore is injected, so
// the subagent's visible tools are the SDK generic set (Bash / WebFetch / …).
func (s *Server) wireDelegation() {
	broker := delegation.NewBroker()
	runner := delegation.NewChildRunner(agent.RunSubagentTurn, broker)
	svc := delegation.NewLifecycleService(runner, broker, func() string {
		// Parent session identity: task runs pass ParentSessionID explicitly via
		// the delegate_task tool; chat runs fall back to the current conversation
		// id when the wiring can resolve one (empty otherwise — harmless).
		return ""
	})
	s.delegationSvc = svc

	// Durable subagent ledger: every launch/state/result transition is mirrored
	// to subagent_runs so the UI can list children and a restart can recover
	// orphaned (non-terminal) rows. Best-effort: a DB failure never blocks the
	// in-memory lifecycle.
	if s.m.pg != nil {
		svc.SetPersistence(s.m.pg)
		if n, err := s.m.pg.RecoverStuckSubagents(); err != nil {
			log.Printf("[delegation] recover subagent ledger: %v", err)
		} else if n > 0 {
			log.Printf("[delegation] recovered %d orphaned subagent runs (interrupted by restart)", n)
		}
	}

	agent.BuildDelegateTool = func() actool.CoreTool {
		return delegation.NewDelegateTool(delegation.DelegateToolOptions{
			Service: svc,
			Broker:  broker,
		})
	}
	agent.ChildProviderFor = func(cfg delegation.ChildConfig) (llm.Provider, error) {
		prov, _, ok := s.globalProvider()
		if !ok {
			return nil, fmt.Errorf("no LLM provider configured; set one in the LLM settings (or ARTEX_LLM_*) to enable subagents")
		}
		return prov, nil
	}
	agent.ChildStore = func() *db.ExplorationStore {
		// Subagents are task-less by construction: no ExplorationStore, so the
		// domain tools that require one are unavailable. The child still has the
		// SDK generic tools to carry out its goal.
		return nil
	}
	agent.ChildWorkDir = s.m.dir
	agent.ChildProxy = func() (string, string) {
		return s.m.ProxyAddr(), s.m.ProxyCACert()
	}
}
