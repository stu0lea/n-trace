//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestConditionExpr(t *testing.T) {
	cases := []struct {
		name string
		cond filterCond
		want string
	}{
		{"bool", filterCond{field: FieldMeta{Name: "outbound", Type: "bool"}, value: "出站"}, "outbound=1"},
		{"int", filterCond{field: FieldMeta{Name: "dst_port", Type: "int"}, value: "443"}, "dst_port=443"},
		{"text-space", filterCond{field: FieldMeta{Name: "image", Type: "text"}, value: `C:\Program Files\a.exe`}, `image:"C:\Program Files\a.exe"`},
		{"text-not-contains", filterCond{field: FieldMeta{Name: "image", Type: "text"}, op: "!:", value: "chrome"}, "image!:chrome"},
		{"date", filterCond{field: FieldMeta{Name: "ts", Type: "time"}, value: "2026-11-07"}, "ts>=2026-11-07"},
	}
	for _, tc := range cases {
		got, err := conditionExpr(tc.cond)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestJoinTimeFilterExpr(t *testing.T) {
	expr := `(ts>="2026-11-07 19:38:33" and ts<"2026-11-07 19:40:00")`
	got := joinFilterExpr("host=HOME-WIN", expr, "OR")
	if got != "host=HOME-WIN OR "+expr {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(got, " OR (") {
		t.Fatalf("OR 必须出现在括号前：%q", got)
	}
}

func TestProcessFieldsAreFilterable(t *testing.T) {
	for _, field := range processFields {
		if _, _, err := processField(field.Name); err != nil {
			t.Fatalf("进程下拉字段 %q 不可筛选: %v", field.Label, err)
		}
	}
}

func TestSyntaxCueHasCompleteExamples(t *testing.T) {
	cases := map[int]string{
		0: "dst_ip:203.0.113.10 and dst_port=443",
		1: "image:*chrome.exe",
		2: "query:example.com",
	}
	for tab, example := range cases {
		if cue := syntaxCueForTab(tab); !strings.Contains(cue, "示例："+example) {
			t.Fatalf("页签 %d 的语法示例不完整：%q", tab, cue)
		}
	}
}

func TestSyntaxHelpKeepsCommonRulesAndAddsTableFields(t *testing.T) {
	conn := syntaxHelpText(0, promoted)
	proc := syntaxHelpText(1, processFields)
	dns := syntaxHelpText(2, dnsFields)

	for name, text := range map[string]string{"连接": conn, "进程": proc, "DNS": dns} {
		for _, common := range []string{"field:value", "field!:value", "field=value", "and / or / not", "ts>=2026-11-01"} {
			if !strings.Contains(text, common) {
				t.Fatalf("%s语法缺少公共规则 %q", name, common)
			}
		}
	}
	for _, want := range []string{"dst_ip:203.0.113.10", "dst_host:example.com", "risk:R6", "非常规端口外联"} {
		if !strings.Contains(conn, want) {
			t.Fatalf("连接语法缺少专用内容 %q", want)
		}
	}
	for _, want := range []string{"cmdline:*powershell*", "parent:*services.exe", "hashes:SHA256", "进程GUID"} {
		if !strings.Contains(proc, want) {
			t.Fatalf("进程语法缺少专用内容 %q", want)
		}
	}
	for _, want := range []string{"query:*.github.com", "results:203.0.113.10", "rule:github-api", "查询域名"} {
		if !strings.Contains(dns, want) {
			t.Fatalf("DNS 语法缺少专用内容 %q", want)
		}
	}
	if strings.Contains(proc, "dst_ip:203.0.113.10") || strings.Contains(dns, "public=1") {
		t.Fatal("进程/DNS 语法不应混入连接表专用字段")
	}
}

func TestDefaultFilterFieldPerTab(t *testing.T) {
	cases := []struct {
		name   string
		tab    int
		fields []FieldMeta
		want   string
	}{
		{"连接", 0, promoted, "dst_ip"},
		{"进程", 1, processFields, "image"},
		{"DNS", 2, dnsFields, "query"},
	}
	for _, tc := range cases {
		idx := defaultFieldIndex(tc.tab, tc.fields)
		if idx < 0 || idx >= len(tc.fields) || tc.fields[idx].Name != tc.want {
			t.Fatalf("%s默认字段应为 %s，得到索引 %d", tc.name, tc.want, idx)
		}
	}
}

func syntaxHelpText(tab int, fields []FieldMeta) string {
	var b strings.Builder
	for _, row := range syntaxHelpRows(tab, fields) {
		b.WriteString(strings.Join(row[:], " "))
		b.WriteByte('\n')
	}
	return b.String()
}
