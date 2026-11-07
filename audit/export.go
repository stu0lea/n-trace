package main

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"
)

var exportHeader = []string{
	"时间", "主机", "进程", "命令行", "用户", "PID", "进程GUID", "父进程", "协议", "方向",
	"源IP", "源端口", "目的IP", "目的端口", "域名", "端口名", "归属地",
	"公网", "风险规则", "进程哈希", "来源",
}

func startCSV(w io.Writer, header []string) (*csv.Writer, error) {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return nil, err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return nil, err
	}
	return cw, nil
}

// exportCSV 把筛选结果流式写成带 BOM 的 CSV；网页下载与原生导出共用。
func exportCSV(d *DB, w io.Writer, expr string, loc *time.Location, progress func(int)) (int, error) {
	rows, err := d.ExportRows(expr)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	cw, err := startCSV(w, exportHeader)
	if err != nil {
		return 0, err
	}

	n := 0
	for rows.Next() {
		c, err := scanConnWithRaw(rows, false)
		if err != nil {
			return n, err
		}
		dir := "入站"
		if c.Out {
			dir = "出站"
		}
		pub := "内网"
		if c.Public {
			pub = "公网"
		}
		if err := cw.Write([]string{
			time.UnixMilli(c.TS).In(loc).Format("2006-01-02 15:04:05.000"),
			c.Host, c.Image, c.CmdLine, c.User, c.PID, c.Guid, c.Parent, c.Proto, dir,
			c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.DstHost, c.PortNm, c.Geo, pub,
			strings.Join(c.Risk, " "), c.Hashes, c.Source,
		}); err != nil {
			return n, err
		}
		n++
		if progress != nil && n%500 == 0 {
			progress(n)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return n, err
	}
	return n, rows.Err()
}

func exportProcessCSV(d *DB, w io.Writer, expr string, loc *time.Location, progress func(int)) (int, error) {
	rows, err := d.ExportProcs(expr)
	if err != nil {
		return 0, err
	}
	cw, err := startCSV(w, []string{
		"主机", "进程", "PID", "用户", "进程GUID", "命令行", "父进程", "哈希",
		"规则", "启动时间", "结束时间", "连接数", "公网连接数", "目的IP数",
		"首次外联", "最近外联", "风险条数", "来源",
	})
	if err != nil {
		return 0, err
	}
	for i, p := range rows {
		if err := cw.Write([]string{
			p.Host, p.Image, p.PID, p.User, p.Guid, p.CmdLine, p.Parent, p.Hashes,
			p.Rule, processTimeText(p.Start, loc), processTimeText(p.End, loc),
			strconv.Itoa(p.N), strconv.Itoa(p.Pub), strconv.Itoa(p.IPs),
			processTimeText(p.First, loc), processTimeText(p.Last, loc),
			strconv.Itoa(p.Risky), p.Source,
		}); err != nil {
			return i, err
		}
		if progress != nil && (i+1)%200 == 0 {
			progress(i + 1)
		}
	}
	cw.Flush()
	return len(rows), cw.Error()
}

func exportDNSCSV(d *DB, w io.Writer, expr string, loc *time.Location, progress func(int)) (int, error) {
	rows, err := d.ExportDNSRows(expr)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cw, err := startCSV(w, []string{"时间", "主机", "进程", "PID", "进程GUID", "用户",
		"查询域名", "解析结果", "归属地", "国家/地区", "风险", "状态", "规则"})
	if err != nil {
		return 0, err
	}
	n := 0
	for rows.Next() {
		var ts int64
		var host, pid, guid, image, user, query, results, geo, country, risk, status, rule string
		if err := rows.Scan(&ts, &host, &pid, &guid, &image, &user, &query, &results,
			&geo, &country, &risk, &status, &rule); err != nil {
			return n, err
		}
		if err := cw.Write([]string{
			time.UnixMilli(ts).In(loc).Format("2006-01-02 15:04:05.000"),
			host, image, pid, guid, user, query, results, geo, country, risk, status, rule,
		}); err != nil {
			return n, err
		}
		n++
		if progress != nil && n%500 == 0 {
			progress(n)
		}
	}
	cw.Flush()
	return n, rows.Err()
}

func exportRiskCSV(d *DB, w io.Writer, expr string) (int, error) {
	counts, err := d.RiskCounts(expr)
	if err != nil {
		return 0, err
	}
	cw, err := startCSV(w, []string{"规则", "说明", "命中数"})
	if err != nil {
		return 0, err
	}
	for i, c := range counts {
		if err := cw.Write([]string{c.Key, ruleText[c.Key], strconv.Itoa(c.N)}); err != nil {
			return i, err
		}
	}
	cw.Flush()
	return len(counts), cw.Error()
}
