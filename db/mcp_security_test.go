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
