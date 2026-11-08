package main

import (
	"path/filepath"
	"testing"
)

func TestRepeatedBackfillDoesNotDuplicateRows(t *testing.T) {
	d, err := openDB(filepath.Join(t.TempDir(), "audit.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	guid := "{idempotent-process}"
	events := []rawEvent{
		{
			EID: "1", Rec: "100", Host: "host", Channel: defaultChannel, TS: 1000,
			F: map[string]string{
				"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Windows\System32\test.exe`,
				"CommandLine": "test.exe", "User": "user",
			},
		},
		{
			EID: "3", Rec: "101", Host: "host", Channel: defaultChannel, TS: 1100,
			F: map[string]string{
				"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Windows\System32\test.exe`,
				"Protocol": "tcp", "DestinationIp": "192.168.1.10",
				"DestinationPort": "443", "Initiated": "true",
			},
		},
		{
			EID: "22", Rec: "102", Host: "host", Channel: defaultChannel, TS: 1200,
			F: map[string]string{
				"ProcessGuid": guid, "ProcessId": "42", "Image": `C:\Windows\System32\test.exe`,
				"QueryName": "example.test", "QueryResults": "192.168.1.10", "QueryStatus": "0",
			},
		},
	}

	for i := 0; i < 2; i++ {
		if _, _, err := d.Ingest(events, liveSource); err != nil {
			t.Fatalf("第 %d 次补读失败: %v", i+1, err)
		}
	}

	totals, err := d.LogTotals()
	if err != nil {
		t.Fatal(err)
	}
	if totals.Connections != 1 || totals.Processes != 1 || totals.DNS != 1 {
		t.Fatalf("重复补读后总数错误: %+v", totals)
	}
	var processEvents int
	if err := d.sql.QueryRow(`SELECT count(*) FROM process_list`).Scan(&processEvents); err != nil {
		t.Fatal(err)
	}
	if processEvents != 1 {
		t.Fatalf("process_list=%d，want 1", processEvents)
	}
}
