package main

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestCleanupRetentionDeletesOldKeepsNew(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	now := time.Now().UnixMilli()
	old := now - 200*24*time.Hour.Milliseconds()
	conns := []*Conn{
		{TS: old, PID: "1", Image: "old.exe", Proto: "tcp", SrcIP: "10.0.0.1", SrcPort: "1", DstIP: "1.1.1.1", DstPort: "80", Guid: "g-old"},
		{TS: now, PID: "2", Image: "new.exe", Proto: "tcp", SrcIP: "10.0.0.2", SrcPort: "2", DstIP: "2.2.2.2", DstPort: "80", Guid: "g-new"},
	}
	dnss := []*DNSQ{
		{TS: old, Query: "old.example.com", Results: "1.1.1.1", Status: "0"},
		{TS: now, Query: "new.example.com", Results: "2.2.2.2", Status: "0"},
	}
	if _, err := d.writeBatch("test.evtx", conns, dnss, nil, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}

	deleted, err := d.CleanupRetention(90, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	if deleted < 2 {
		t.Fatalf("至少应删除 conn+dns 两条，实际 %d", deleted)
	}
	if n, _ := d.Count(""); n != 1 {
		t.Fatalf("新连接应保留，实际 conn=%d", n)
	}
	if n, _ := d.CountDNSFiltered(""); n != 1 {
		t.Fatalf("新 DNS 应保留，实际 dns=%d", n)
	}
	// 全文索引同步删除：旧记录不应再被搜索到。
	if n, _ := d.Count("old.exe"); n != 0 {
		t.Fatalf("旧记录应被清理，命中 %d", n)
	}
	if n, _ := d.Count("new.exe"); n != 1 {
		t.Fatalf("新记录应可搜索，命中 %d", n)
	}
}

func TestStoreRawDisabledSkipsRawJSON(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetStoreRaw(false)

	c := &Conn{
		TS: 1000, PID: "42", Image: "test.exe", Proto: "tcp",
		SrcIP: "10.0.0.1", SrcPort: "50000", DstIP: "203.0.113.10", DstPort: "443",
		Raw: map[string]string{"DestinationIp": "203.0.113.10"},
	}
	if _, err := d.writeBatch("test.evtx", []*Conn{c}, nil, nil, map[string]int{}, 1, false); err != nil {
		t.Fatal(err)
	}
	full, err := d.ConnByID(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Raw) != 0 {
		t.Fatalf("store_raw=false 时不应保存原始事件，得到 %#v", full.Raw)
	}
}

func TestCleanupRetentionProcessAggregates(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	now := time.Now().UnixMilli()
	old := now - 200*24*time.Hour.Milliseconds()
	procs := []*ProcessEvent{
		{EventID: 1, TS: old, Guid: "g-old", PID: "100", Image: `C:\old.exe`},
		{EventID: 1, TS: now, Guid: "g-new", PID: "200", Image: `C:\new.exe`},
	}
	if _, err := d.writeBatch("test.evtx", nil, nil, procs, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	// 两个进程各关联一个目的 IP；旧进程清理后其 IP 关联也应被删除。
	for _, g := range []string{"g-old", "g-new"} {
		if _, err := d.sql.Exec(`INSERT INTO process_ip(guid,dst_ip) VALUES(?,?)`, g, "1.2.3.4"); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := d.CleanupRetention(90, func(string, ...interface{}) {}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.sql.QueryRow(`SELECT count(*) FROM process_list WHERE guid='g-old'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("过期进程聚合行应被删除，n=%d err=%v", n, err)
	}
	if err := d.sql.QueryRow(`SELECT count(*) FROM process_list WHERE guid='g-new'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("未过期进程聚合行应保留，n=%d err=%v", n, err)
	}
	if err := d.sql.QueryRow(`SELECT count(*) FROM process_ip WHERE guid='g-old'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("孤儿 IP 关联应被删除，n=%d err=%v", n, err)
	}
	if err := d.sql.QueryRow(`SELECT count(*) FROM process_ip WHERE guid='g-new'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("未过期进程的 IP 关联应保留，n=%d err=%v", n, err)
	}
}

func TestCleanupRetentionLargeBatch(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// 超过单批（5000）的行数，验证循环删除能清干净且全文索引保持一致。
	old := time.Now().AddDate(0, 0, -200).UnixMilli()
	conns := make([]*Conn, 0, 6000)
	for i := 0; i < 6000; i++ {
		conns = append(conns, &Conn{
			TS: old, PID: strconv.Itoa(i), Image: "bulk.exe", Proto: "tcp",
			SrcIP: "10.0.0.1", SrcPort: strconv.Itoa(40000 + i%10000),
			DstIP: "203.0.113." + strconv.Itoa(i%200+1), DstPort: "80",
			Guid: "g-bulk-" + strconv.Itoa(i),
		})
	}
	if _, err := d.writeBatch("test.evtx", conns, nil, nil, map[string]int{}, len(conns), false); err != nil {
		t.Fatal(err)
	}

	deleted, err := d.CleanupRetention(90, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	// 删除计数包含 conn 及其派生的 process_list 聚合行，至少应等于 conn 数。
	if deleted < 6000 {
		t.Fatalf("应至少删除 6000 条，实际 %d", deleted)
	}
	if n, _ := d.Count(""); n != 0 {
		t.Fatalf("清理后 conn 应为空，实际 %d", n)
	}
	if n, _ := d.Count("bulk.exe"); n != 0 {
		t.Fatalf("全文索引不应再命中已删除记录，命中 %d", n)
	}
}
