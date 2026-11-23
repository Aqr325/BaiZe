package db

import (
	"strings"
	"testing"
)

func TestMCPSecurityEvents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// Isolate from any real events with a unique tool marker.
	marker := "test-mcp-security-event"
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM mcp_security_events WHERE tool_name=$1`, marker)
	})

	for _, e := range []MCPSecurityEvent{
		{Kind: "pin", ServerName: "srv-a", ToolName: marker, Detail: "desc changed"},
		{Kind: "shadow", ServerName: "srv-b", ToolName: marker, Detail: "name collision"},
	} {
		if err := d.InsertMCPSecurityEvent(e); err != nil {
			t.Fatalf("insert %s: %v", e.Kind, err)
		}
	}

	all, err := d.ListMCPSecurityEvents("", 50)
	if err != nil {
		t.Fatal(err)
	}
	var pin, shadow int
	for _, e := range all {
		if e.ToolName != marker {
			continue
		}
		switch e.Kind {
		case "pin":
			pin++
			if !strings.Contains(e.Detail, "desc changed") {
				t.Fatalf("pin detail lost: %q", e.Detail)
			}
		case "shadow":
			shadow++
		}
	}
	if pin != 1 || shadow != 1 {
		t.Fatalf("expected pin=1 shadow=1 for marker, got pin=%d shadow=%d", pin, shadow)
	}

	// kind filter
	pins, err := d.ListMCPSecurityEvents("pin", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pins {
		if e.Kind != "pin" {
			t.Fatalf("kind filter leaked %q", e.Kind)
		}
	}
}

func TestMCPToolQuarantineLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	srv, tool := "test-pin-srv", "test-pin-tool"
	q := MCPToolQuarantine{
		ServerName: srv, ToolName: tool,
		OldHash: "aaa", NewHash: "bbb",
		Detail: "描述变更", DetectedAt: "2026-11-23T22:00:00Z",
	}
	t.Cleanup(func() {
		_ = d.ClearMCPToolQuarantine(srv, tool)
		_ = d.DeleteSetting("mcp_tool_desc_hash:" + srv + ":" + tool)
	})

	if err := d.SaveMCPToolQuarantine(q); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetMCPToolQuarantine(srv, tool)
	if err != nil || got == nil || got.NewHash != "bbb" {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, err := d.ListMCPToolQuarantines()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range list {
		if item.ServerName == srv && item.ToolName == tool {
			found = true
		}
	}
	if !found {
		t.Fatal("quarantine not listed")
	}

	// approve advances baseline to the new hash and clears quarantine
	approved, err := d.ApproveMCPToolQuarantine(srv, tool)
	if err != nil || approved == nil {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	base, ok, err := d.GetMCPPinBaseline(srv, tool)
	if err != nil || !ok || base != "bbb" {
		t.Fatalf("baseline after approve: %q ok=%v %v", base, ok, err)
	}
	got, err = d.GetMCPToolQuarantine(srv, tool)
	if err != nil || got != nil {
		t.Fatalf("quarantine should be cleared: %+v %v", got, err)
	}
	// idempotent approve on missing → nil, no error
	again, err := d.ApproveMCPToolQuarantine(srv, tool)
	if err != nil || again != nil {
		t.Fatalf("approve again: %+v %v", again, err)
	}
}
