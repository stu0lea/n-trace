package main

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"testing"
)

func TestQueryLiteSkipsRawAndDetailLoadsIt(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	c := &Conn{
		TS: 1000, Host: "host", PID: "42", Image: `C:\Windows\System32\test.exe`,
		Proto: "tcp", SrcIP: "10.0.0.1", SrcPort: "50000",
		DstIP: "203.0.113.10", DstPort: "443", Out: true, Public: true,
		Raw: map[string]string{"DestinationIp": "203.0.113.10", "Initiated": "true"},
	}
	if _, err := d.writeBatch("test.evtx", []*Conn{c}, nil, nil, map[string]int{}, 1, false); err != nil {
		t.Fatal(err)
	}

	if n, err := d.Count("203.0.113.10"); err != nil || n != 1 {
		t.Fatalf("全局搜索应命中目的 IP：n=%d err=%v", n, err)
	}

	rows, err := d.QueryLite("", 10, 0, "ts", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("QueryLite returned %d rows, want 1", len(rows))
	}
	if rows[0].Raw != nil {
		t.Fatalf("QueryLite should not load raw JSON")
	}

	full, err := d.ConnByID(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Raw["Initiated"] != "true" {
		t.Fatalf("ConnByID raw = %#v", full.Raw)
	}
}

func TestMigrateLegacyDNSGeoColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE dns(
		id INTEGER PRIMARY KEY, ts INTEGER, host TEXT, pid TEXT, guid TEXT,
		image TEXT, user TEXT, query TEXT, results TEXT, status TEXT, raw TEXT, source TEXT
	)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO dns(ts,query,results,status) VALUES
		(1000,'example.com','1.2.3.4','0'),
		(1000,'example.com','1.2.3.4','0')`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	raw.Close()

	d, err := openDB(path, nil)
	if err != nil {
		t.Fatalf("旧 DNS 表升级失败: %v", err)
	}
	defer d.Close()
	for _, col := range []string{"geo", "country", "risk"} {
		if !d.hasColumn("dns", col) {
			t.Fatalf("升级后缺少 dns.%s", col)
		}
	}
	if n, err := d.CountDNS(); err != nil || n != 1 {
		t.Fatalf("DNS 历史重复数据未去重: n=%d err=%v", n, err)
	}
}

func TestCompileRequiresExplicitAnd(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, _, err := d.compile("image:chrome dst_port=443"); err == nil {
		t.Fatal("空格分隔的条件应当报错，必须显式写 AND")
	}
	if _, _, err := d.compile("image:chrome and dst_port=443"); err != nil {
		t.Fatalf("显式 AND 应当可用：%v", err)
	}
	if _, _, err := d.compile(`ts>="2026-11-07 18:00:00"`); err != nil {
		t.Fatalf("含空格的时间值应使用引号：%v", err)
	}
	for _, tc := range []struct {
		token string
		op    string
		idx   int
	}{
		{`image=C:\Program Files\WPS Office\wps.exe`, "=", 5},
		{`dst_ip:203.0.113.10`, ":", 6},
		{`hashes:SHA256=abc`, ":", 6},
		{`pid!=4`, "!=", 3},
		{`ts>=2026-11-01`, ">=", 2},
	} {
		op, idx := findOp(tc.token)
		if op != tc.op || idx != tc.idx {
			t.Fatalf("findOp(%q) = %q,%d，期望 %q,%d", tc.token, op, idx, tc.op, tc.idx)
		}
	}
}

func TestDNSFieldsRoundTrip(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	q := &DNSQ{
		TS: 1000, Host: "host", PID: "42", Guid: "{guid}", Image: `C:\test.exe`,
		User: "user", Query: "example.com", Results: "1.2.3.4", Status: "0",
		Geo: "美国", Country: "US", Risk: []string{dnsRiskForeign},
		Rule: "-", Raw: map[string]string{"RuleName": "-", "QueryType": "1"},
	}
	if _, err := d.writeBatch("test.evtx", nil, []*DNSQ{q}, nil, map[string]int{}, 1, false); err != nil {
		t.Fatal(err)
	}
	rows, total, err := d.QueryDNS("query:example.com", 10)
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("QueryDNS total=%d rows=%d err=%v", total, len(rows), err)
	}
	if rows[0].Rule != "-" || rows[0].PID != "42" || rows[0].Guid != "{guid}" ||
		rows[0].Geo != "美国" || rows[0].Country != "US" || !hasRisk(rows[0].Risk, dnsRiskForeign) {
		t.Fatalf("DNS 字段缺失: %+v", rows[0])
	}
	if _, n, err := d.QueryDNS("example.com", 10); err != nil || n != 1 {
		t.Fatalf("DNS 全文筛选失败: n=%d err=%v", n, err)
	}
	if _, n, err := d.QueryDNS("image:no-match", 10); err != nil || n != 0 {
		t.Fatalf("DNS 字段筛选失败: n=%d err=%v", n, err)
	}
	if _, n, err := d.QueryDNS("risk:D1", 10); err != nil || n != 1 {
		t.Fatalf("DNS 风险筛选失败: n=%d err=%v", n, err)
	}
	if _, n, err := d.QueryDNS("geo:美国", 10); err != nil || n != 1 {
		t.Fatalf("DNS 归属地筛选失败: n=%d err=%v", n, err)
	}
	stats, err := d.DNSStats("query:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 || stats.Domains != 1 || stats.Results != 1 ||
		len(stats.TopDomain) != 1 || stats.TopDomain[0].Key != "example.com" {
		t.Fatalf("DNS 独立统计错误: %+v", stats)
	}
	if len(stats.TopProcess) != 1 || stats.TopProcess[0].Key != `C:\test.exe` {
		t.Fatalf("DNS TOP 进程统计错误: %+v", stats.TopProcess)
	}
	if len(stats.TopResult) != 1 || stats.TopResult[0].Key != "1.2.3.4" {
		t.Fatalf("DNS TOP 解析 IP 统计错误: %+v", stats.TopResult)
	}
	if stats.Foreign != 1 || len(stats.Risks) == 0 || stats.Risks[0].Key != dnsRiskForeign || stats.Risks[0].N != 1 {
		t.Fatalf("DNS 风险统计错误: foreign=%d risks=%+v", stats.Foreign, stats.Risks)
	}
	if n, err := d.CountDNS(); err != nil || n != 1 {
		t.Fatalf("DNS 固定总数错误: n=%d err=%v", n, err)
	}
	if n, err := d.CountDNSFiltered("query:example.com"); err != nil || n != 1 {
		t.Fatalf("DNS 筛选总数错误: n=%d err=%v", n, err)
	}
	if n, err := d.CountDNSFiltered("image:no-match"); err != nil || n != 0 {
		t.Fatalf("DNS 筛选空结果错误: n=%d err=%v", n, err)
	}
}

func TestQueryDNSWithoutLimitReturnsAll(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	dnsRows := []*DNSQ{
		{TS: 1000, Guid: "{a}", Query: "a.example.com", Results: "1.1.1.1", Status: "0"},
		{TS: 2000, Guid: "{b}", Query: "b.example.com", Results: "2.2.2.2", Status: "0"},
	}
	if _, err := d.writeBatch("test.evtx", nil, dnsRows, nil, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	rows, total, err := d.QueryDNS("", 0)
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("无上限 DNS 查询 total=%d rows=%d err=%v", total, len(rows), err)
	}
	page, err := d.PageDNS("", 1, 0, "query", false)
	if err != nil || len(page) != 1 || page[0].Query != "a.example.com" {
		t.Fatalf("DNS 分页排序失败: rows=%+v err=%v", page, err)
	}
}

func TestLogTotalsIncludeConnectionsProcessesDNS(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	conns := []*Conn{{TS: 1000, Guid: "{conn}", Image: "a.exe"}}
	dnsRows := []*DNSQ{{TS: 1000, Guid: "{dns}", Query: "example.com"}}
	procs := []*ProcessEvent{{EventID: 1, TS: 1000, Guid: "{proc}", Image: "b.exe"}}
	if _, err := d.writeBatch("test.evtx", conns, dnsRows, procs, map[string]int{}, 3, false); err != nil {
		t.Fatal(err)
	}
	totals, err := d.LogTotals()
	if err != nil {
		t.Fatal(err)
	}
	if totals.Connections != 1 || totals.Processes != 2 || totals.DNS != 1 {
		t.Fatalf("日志总计不完整: %+v", totals)
	}
}

func TestProcessAggregateUsesLatestPID(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	guid := "{test-guid}"
	conns := []*Conn{
		{
			TS: 1000, Host: "host", PID: "100", Guid: guid, Image: "a.exe", Proto: "tcp",
			DstIP: "1.1.1.1", DstPort: "443", Raw: map[string]string{},
		},
		{
			TS: 2000, Host: "host", PID: "200", Guid: guid, Image: "a.exe", Proto: "tcp",
			DstIP: "1.1.1.1", DstPort: "443", Raw: map[string]string{},
		},
	}
	if _, err := d.writeBatch("test.evtx", conns, nil, nil, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	rows, err := d.QueryProcs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].PID != "200" {
		t.Fatalf("应取最新 PID 200，得到 %+v", rows)
	}
}

func TestProcessFilterExactImageIsolation(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	wps := `C:\Program Files\WPS Office\wps.exe`
	conns := []*Conn{
		{TS: 1000, Guid: "{wps}", Image: wps, PID: "10", Proto: "tcp", DstIP: "1.1.1.1"},
		{TS: 1001, Guid: "{other}", Image: `C:\Windows\System32\conhost.exe`, PID: "20", Proto: "tcp", DstIP: "2.2.2.2"},
	}
	procs := []*ProcessEvent{
		{EventID: 1, TS: 1000, Guid: "{wps}", Image: wps, PID: "10", User: "user"},
		{EventID: 1, TS: 1001, Guid: "{other}", Image: `C:\Windows\System32\conhost.exe`, PID: "20", User: "user"},
	}
	if _, err := d.writeBatch("test.evtx", conns, nil, procs, map[string]int{}, 4, false); err != nil {
		t.Fatal(err)
	}
	expr := `image="` + wps + `"`
	rows, err := d.QueryProcs(expr)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Guid != "{wps}" || rows[0].Image != wps {
		t.Fatalf("精确进程筛选应只返回 WPS，得到 %+v", rows)
	}
}

func TestPageProcsSortAndOffset(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	procs := []*ProcessEvent{
		{EventID: 1, TS: 1000, Guid: "{b}", Image: "b.exe", PID: "2"},
		{EventID: 1, TS: 2000, Guid: "{a}", Image: "a.exe", PID: "1"},
	}
	if _, err := d.writeBatch("test.evtx", nil, nil, procs, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	page, err := d.PageProcs("", 1, 0, "image", false)
	if err != nil || len(page) != 1 || page[0].Image != "a.exe" {
		t.Fatalf("进程分页排序失败: rows=%+v err=%v", page, err)
	}
}

func TestFieldsHideRawEnglishAliases(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.sql.Exec(`INSERT INTO rawfield(name,n) VALUES
		('Image',1),('SourceHostname',1),('UnknownEnglishField',1)`); err != nil {
		t.Fatal(err)
	}
	fields, err := d.Fields()
	if err != nil {
		t.Fatal(err)
	}
	foundSourceHost := false
	for _, f := range fields {
		if f.Label == "Image" || f.Label == "UnknownEnglishField" {
			t.Fatalf("下拉不应显示英文原始字段: %+v", f)
		}
		if f.Label == "源主机名" && f.Name == "SourceHostname" {
			foundSourceHost = true
		}
	}
	if !foundSourceHost {
		t.Fatal("缺少翻译后的源主机名字段")
	}
}

func TestProcessEventsPersistWithoutConnections(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	guid := "{proc-guid}"
	start := rawEvent{
		EID: "1", TS: 1000, Host: "host",
		F: map[string]string{
			"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Windows\System32\test.exe`,
			"CommandLine": `test.exe -x`, "User": "user", "IntegrityLevel": "High",
			"Hashes": "SHA256=abc", "ParentProcessGuid": "{parent}", "ParentProcessId": "4",
			"ParentImage": `C:\Windows\System32\services.exe`,
		},
	}
	end := rawEvent{
		EID: "5", TS: 2000, Host: "host",
		F: map[string]string{"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Windows\System32\test.exe`},
	}
	if _, _, err := d.Ingest([]rawEvent{start, end}, "test.evtx"); err != nil {
		t.Fatal(err)
	}
	rows, err := d.QueryProcs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("process rows=%d, want 1", len(rows))
	}
	p := rows[0]
	if p.Guid != guid || p.Image != `C:\Windows\System32\test.exe` || p.PID != "42" ||
		p.Start != 1000 || p.End != 2000 || p.N != 0 {
		t.Fatalf("进程事件未正确持久化/聚合: %+v", p)
	}

	rows, err = d.QueryProcs("parent_guid:{parent} and hashes:SHA256=abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Guid != guid {
		t.Fatalf("进程独立筛选应命中无网络连接的进程: %+v", rows)
	}
	if _, _, err := d.compileProcess("dst_port=443"); err == nil {
		t.Fatal("进程筛选不应接受仅连接页支持的字段")
	}
	vals, err := d.ProcessValuesFiltered("image", 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 || vals[0].Key != `C:\Windows\System32\test.exe` || vals[0].N != 1 {
		t.Fatalf("进程热门数据统计错误: %+v", vals)
	}
	stats, err := d.ProcessStats("parent_guid:{parent}")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 1 || stats.WithoutNetwork != 1 || stats.Ended != 1 {
		t.Fatalf("进程独立统计错误: %+v", stats)
	}
	if len(stats.TopProcess) != 1 || stats.TopProcess[0].Key != `C:\Windows\System32\test.exe` {
		t.Fatalf("进程 TOP 统计错误: %+v", stats.TopProcess)
	}
	if len(stats.TopParent) != 1 || stats.TopParent[0].Key != `C:\Windows\System32\services.exe` {
		t.Fatalf("进程 TOP 父进程统计错误: %+v", stats.TopParent)
	}
	if n, err := d.CountProcesses(); err != nil || n != 1 {
		t.Fatalf("进程固定总数错误: n=%d err=%v", n, err)
	}
	if n, err := d.CountProcessesFiltered("parent_guid:{parent}"); err != nil || n != 1 {
		t.Fatalf("进程筛选总数错误: n=%d err=%v", n, err)
	}
	if n, err := d.CountProcessesFiltered("image:no-match"); err != nil || n != 0 {
		t.Fatalf("进程筛选空结果错误: n=%d err=%v", n, err)
	}
}

func TestPageAndCount(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	conns := []*Conn{
		{TS: 1, Guid: "a", Image: "a.exe", DstIP: "1.1.1.1", DstPort: "80", Proto: "tcp"},
		{TS: 2, Guid: "b", Image: "b.exe", DstIP: "1.1.1.2", DstPort: "443", Proto: "tcp"},
	}
	if _, err := d.writeBatch("test.evtx", conns, nil, nil, map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	total, err := d.Count("proto:tcp")
	if err != nil || total != 2 {
		t.Fatalf("Count = %d, %v", total, err)
	}
	rows, err := d.Page("", 1, 1, "ts", false)
	if err != nil || len(rows) != 1 || rows[0].TS != 2 {
		t.Fatalf("Page = %#v, %v", rows, err)
	}
}

func TestPaginationStableForDuplicateTimestamps(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var conns []*Conn
	var dnss []*DNSQ
	var procs []*ProcessEvent
	for i := 0; i < 7; i++ {
		id := strconv.Itoa(i)
		conns = append(conns, &Conn{
			TS: 1000, Guid: "conn-" + id, Image: "a.exe", DstIP: "10.0.0." + id,
			DstPort: "443", Proto: "tcp",
		})
		dnss = append(dnss, &DNSQ{TS: 1000, Guid: "dns-" + id, Query: "example.com"})
		procs = append(procs, &ProcessEvent{EventID: 1, TS: 1000, Guid: "proc-" + id, Image: "a.exe"})
	}
	if _, err := d.writeBatch("test.evtx", conns, dnss, procs, map[string]int{}, 21, false); err != nil {
		t.Fatal(err)
	}

	seenConn := map[int64]bool{}
	for offset := 0; offset < 7; offset += 2 {
		rows, err := d.QueryLite("", 2, offset, "ts", true)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seenConn[row.ID] {
				t.Fatalf("连接分页重复行 id=%d", row.ID)
			}
			seenConn[row.ID] = true
		}
	}
	if len(seenConn) != 7 {
		t.Fatalf("连接分页行数=%d，want 7", len(seenConn))
	}

	seenDNS := map[string]bool{}
	for offset := 0; offset < 7; offset += 2 {
		rows, err := d.PageDNS("", 2, offset, "ts", true)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seenDNS[row.Guid] {
				t.Fatalf("DNS 分页重复行 guid=%s", row.Guid)
			}
			seenDNS[row.Guid] = true
		}
	}
	if len(seenDNS) != 7 {
		t.Fatalf("DNS 分页行数=%d，want 7", len(seenDNS))
	}

	seenProc := map[string]bool{}
	for offset := 0; offset < 20; offset += 2 {
		rows, err := d.PageProcs("", 2, offset, "start", true)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seenProc[row.Guid] {
				t.Fatalf("进程分页重复行 guid=%s", row.Guid)
			}
			seenProc[row.Guid] = true
		}
	}
	if len(seenProc) != 14 {
		t.Fatalf("进程分页行数=%d，want 14", len(seenProc))
	}
}

func TestSnapshotPaginationIgnoresLiveInserts(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var conns []*Conn
	for i := 0; i < 4; i++ {
		id := strconv.Itoa(i)
		conns = append(conns, &Conn{
			TS: 1000, Guid: "old-" + id, Image: "a.exe", DstIP: "10.0.0." + id,
			DstPort: "443", Proto: "tcp",
		})
	}
	if _, err := d.writeBatch("test.evtx", conns, nil, nil, map[string]int{}, 4, false); err != nil {
		t.Fatal(err)
	}
	snapshotID, err := d.SnapshotMaxID("dst_ip:10.0.0.")
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.QueryLiteBefore("dst_ip:10.0.0.", 2, 0, "ts", true, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.writeBatch("live.evtx", []*Conn{{
		TS: 2000, Guid: "new", Image: "a.exe", DstIP: "10.0.0.9",
		DstPort: "443", Proto: "tcp",
	}}, nil, nil, map[string]int{}, 1, false); err != nil {
		t.Fatal(err)
	}
	second, err := d.QueryLiteBefore("dst_ip:10.0.0.", 2, 2, "ts", true, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	all := append(first, second...)
	if len(all) != 4 {
		t.Fatalf("snapshot rows=%d, want 4", len(all))
	}
	seen := map[int64]bool{}
	for _, row := range all {
		if seen[row.ID] {
			t.Fatalf("snapshot 分页重复 id=%d", row.ID)
		}
		seen[row.ID] = true
		if row.Guid == "new" {
			t.Fatal("snapshot 分页不应包含刷新后新增行")
		}
	}
}

func TestProcessAndDNSSnapshotPagination(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var dnss []*DNSQ
	var procs []*ProcessEvent
	for i := 0; i < 4; i++ {
		id := strconv.Itoa(i)
		dnss = append(dnss, &DNSQ{TS: 1000, Guid: "dns-old-" + id, Query: "old.example.com"})
		procs = append(procs, &ProcessEvent{EventID: 1, TS: 1000, Guid: "proc-old-" + id, Image: "old.exe"})
	}
	if _, err := d.writeBatch("test.evtx", nil, dnss, procs, map[string]int{}, 8, false); err != nil {
		t.Fatal(err)
	}
	firstDNS, err := d.PageDNSAsOf("", 2, 0, "ts", true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	firstProc, err := d.PageProcsAsOf("", 2, 0, "start", true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.writeBatch("live.evtx",
		nil,
		[]*DNSQ{{TS: 2000, Guid: "dns-new", Query: "new.example.com"}},
		[]*ProcessEvent{{EventID: 1, TS: 2000, Guid: "proc-new", Image: "new.exe"}},
		map[string]int{}, 2, false); err != nil {
		t.Fatal(err)
	}
	secondDNS, err := d.PageDNSAsOf("", 2, 2, "ts", true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	secondProc, err := d.PageProcsAsOf("", 2, 2, "start", true, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(append(firstDNS, secondDNS...)) != 4 {
		t.Fatalf("DNS 快照分页行数错误")
	}
	if len(append(firstProc, secondProc...)) != 4 {
		t.Fatalf("进程快照分页行数错误")
	}
	for _, row := range append(firstDNS, secondDNS...) {
		if row.Guid == "dns-new" {
			t.Fatal("DNS 快照分页不应包含新增行")
		}
	}
	for _, row := range append(firstProc, secondProc...) {
		if row.Guid == "proc-new" {
			t.Fatal("进程快照分页不应包含新增行")
		}
	}
}

func TestIRStatsIncludesSinglePrivateTargetIP(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	c := &Conn{
		TS: 1000, Image: "client.exe", DstIP: "192.168.20.1", DstHost: "intranet.local",
		DstPort: "8080", Proto: "tcp", Public: false,
	}
	if _, err := d.writeBatch("test.evtx", []*Conn{c}, nil, nil, map[string]int{}, 1, false); err != nil {
		t.Fatal(err)
	}
	stats, err := d.IRStats("dst_ip=192.168.20.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.TopIP) != 1 || stats.TopIP[0].Key != "192.168.20.1" || stats.TopIP[0].N != 1 {
		t.Fatalf("TOP 目标 IP 应包含单条私网结果: %+v", stats.TopIP)
	}
	if len(stats.TopProc) != 1 || stats.TopProc[0].Key != "client.exe" {
		t.Fatalf("TOP 进程应包含单条结果: %+v", stats.TopProc)
	}
	if len(stats.TopDomain) != 1 || stats.TopDomain[0].Key != "intranet.local" {
		t.Fatalf("TOP 域名应包含单条结果: %+v", stats.TopDomain)
	}
}
