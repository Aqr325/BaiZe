package db

import (
	"testing"
)

// TestPopulateFindingTrafficIDsEnrichesTriage 验证 finding-aware 读取在填充
// traffic_count 的同时带回 triage 三列——这是 Agent list_findings 看到分级的关键。
func TestPopulateFindingTrafficIDsEnrichesTriage(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTask("triage enrich fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID)
		d.DeleteTask(task.ID)
	}()

	// 用高危 RCE 描述 + remote_verified 证据，确保 triage 分级非默认值
	rec, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{
		TaskID:        task.ID,
		ExplorationID: task.ExplorationID,
		VulnClass:     "rce",
		Name:          "triage enrich probe",
		Summary:       "远程命令执行已复现，可未授权执行系统命令",
		Severity:      "critical",
		Evidence:      "curl 触发命令执行并返回 id 输出",
		EvidenceGrade: "remote_verified",
		Worker:        "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	var got *DBFinding
	got, err = d.GetFinding(rec.FindingID)
	if err != nil || got == nil {
		t.Fatalf("GetFinding: %v (nil=%v)", err, got == nil)
	}
	if got.TriageTier <= 0 || got.TriageTier > 6 {
		t.Fatalf("unexpected triage tier in DB: %d", got.TriageTier)
	}

	// 构造一个裸 Node，只带 Kind 和 ID（模拟 ListByKindWithSources 的初始状态）
	node := &Node{ID: rec.NodeID, Kind: KindFinding}
	if err := d.Exploration(task.ExplorationID).PopulateFindingTrafficIDs([]*Node{node}); err != nil {
		t.Fatal(err)
	}

	if node.FindingID != rec.FindingID {
		t.Errorf("finding id: got %d want %d", node.FindingID, rec.FindingID)
	}
	if node.TrafficCount != 0 {
		t.Errorf("traffic count: got %d want 0", node.TrafficCount)
	}
	if node.TriageTier != got.TriageTier {
		t.Errorf("triage tier: node=%d db=%d", node.TriageTier, got.TriageTier)
	}
	if node.HarmPrimitive != got.HarmPrimitive {
		t.Errorf("harm primitive: node=%q db=%q", node.HarmPrimitive, got.HarmPrimitive)
	}
	if node.AssetTier != got.AssetTier {
		t.Errorf("asset tier: node=%q db=%q", node.AssetTier, got.AssetTier)
	}
}
