package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// FieldMeta 描述一个可筛选字段。
type FieldMeta struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Type  string `json:"type"` // text/int/bool/time
	Raw   bool   `json:"raw"`
}

// promoted 是提升为独立列并建索引的字段。
var promoted = []FieldMeta{
	{Name: "ts", Label: "时间", Type: "time"},
	{Name: "host", Label: "主机", Type: "text"},
	{Name: "image", Label: "进程", Type: "text"},
	{Name: "cmdline", Label: "命令行", Type: "text"},
	{Name: "user", Label: "用户", Type: "text"},
	{Name: "pid", Label: "PID", Type: "text"},
	{Name: "guid", Label: "进程GUID", Type: "text"},
	{Name: "parent", Label: "父进程", Type: "text"},
	{Name: "hashes", Label: "哈希", Type: "text"},
	{Name: "integrity", Label: "完整性", Type: "text"},
	{Name: "proto", Label: "协议", Type: "text"},
	{Name: "outbound", Label: "方向", Type: "bool"},
	{Name: "src_ip", Label: "源IP", Type: "text"},
	{Name: "src_port", Label: "源端口", Type: "int"},
	{Name: "dst_ip", Label: "目的IP", Type: "text"},
	{Name: "dst_port", Label: "目的端口", Type: "int"},
	{Name: "dst_host", Label: "域名", Type: "text"},
	{Name: "port_name", Label: "端口名", Type: "text"},
	{Name: "geo", Label: "归属地", Type: "text"},
	{Name: "public", Label: "公网", Type: "bool"},
	{Name: "ipv6", Label: "IPv6", Type: "bool"},
	{Name: "rule_name", Label: "Sysmon规则", Type: "text"},
	{Name: "risk", Label: "风险", Type: "text"},
	{Name: "source", Label: "来源", Type: "text"},
}

var promotedIdx = map[string]FieldMeta{}

var rawFieldAliases = map[string]string{
	"image": "image", "processguid": "guid", "processid": "pid", "user": "user",
	"utctime": "ts", "rulename": "rule_name", "commandline": "cmdline",
	"parentimage": "parent", "hashes": "hashes", "integritylevel": "integrity",
	"protocol": "proto", "initiated": "outbound", "sourceip": "src_ip",
	"sourceport": "src_port", "destinationip": "dst_ip", "destinationport": "dst_port",
	"destinationhostname": "dst_host", "destinationportname": "port_name",
	"destinationisipv6": "ipv6",
}

var rawFieldLabels = map[string]string{
	"sourcehostname":    "源主机名",
	"sourceisipv6":      "源IPv6",
	"sourceportname":    "源端口名",
	"parentcommandline": "父命令行",
	"currentdirectory":  "当前目录",
	"logonid":           "登录ID",
	"terminalsessionid": "终端会话ID",
	"fileversion":       "文件版本",
	"description":       "文件描述",
	"product":           "产品名",
	"company":           "公司",
	"originalfilename":  "原始文件名",
}

var rawFieldIgnored = map[string]bool{
	"queryname": true, "querystatus": true, "queryresults": true,
}

func init() {
	for _, f := range promoted {
		promotedIdx[f.Name] = f
	}
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// DB 是 SQLite 存储。
type DB struct {
	sql *sql.DB
	geo *geoDB
	mu  sync.Mutex

	// 实时采集用：跨批次保留的进程信息与 IP->域名 关联。
	procCache map[string]*procInfo
	ipdns     map[string][]ipDNS
}

func openDB(path string, geo *geoDB) (*DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-65536)&_pragma=temp_store(MEMORY)&_pragma=busy_timeout(5000)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// WAL 模式下允许后台读取与实时写入并行，避免表格查询被单连接串行阻塞。
	sqldb.SetMaxOpenConns(4)
	sqldb.SetMaxIdleConns(4)
	d := &DB{sql: sqldb, geo: geo, procCache: map[string]*procInfo{}, ipdns: map[string][]ipDNS{}}
	if err := d.migrate(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS conn(
			id INTEGER PRIMARY KEY,
			ts INTEGER NOT NULL,
			host TEXT, pid TEXT, guid TEXT, image TEXT, user TEXT,
			proto TEXT, src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port INTEGER,
			dst_host TEXT, port_name TEXT, outbound INTEGER, ipv6 INTEGER,
			geo TEXT, public INTEGER, cmdline TEXT, parent TEXT, hashes TEXT,
			integrity TEXT, rule_name TEXT, risk TEXT, raw TEXT, source TEXT,
			UNIQUE(guid, ts, dst_ip, dst_port, proto)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_ts ON conn(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_ts_id ON conn(ts DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_dstip ON conn(dst_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_image ON conn(image)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_guid ON conn(guid)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_pid ON conn(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_port ON conn(dst_port)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_host ON conn(dst_host)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_geo ON conn(geo)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_risk ON conn(risk)`,
		`CREATE TABLE IF NOT EXISTS dns(
			id INTEGER PRIMARY KEY,
			ts INTEGER, host TEXT, pid TEXT, guid TEXT, image TEXT, user TEXT,
			query TEXT, results TEXT, status TEXT, geo TEXT, country TEXT, risk TEXT,
			raw TEXT, source TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_ts_id ON dns(ts DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_query ON dns(query)`,
		`CREATE TABLE IF NOT EXISTS process_event(
			id INTEGER PRIMARY KEY,
			event_id INTEGER NOT NULL,
			ts INTEGER NOT NULL,
			host TEXT,
			guid TEXT,
			pid TEXT,
			image TEXT,
			cmdline TEXT,
			user TEXT,
			integrity TEXT,
			hashes TEXT,
			parent_guid TEXT,
			parent_pid TEXT,
			parent_image TEXT,
			parent_cmdline TEXT,
			rule_name TEXT,
			raw TEXT,
			source TEXT,
			UNIQUE(guid, event_id, ts)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_process_ts ON process_event(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_process_guid ON process_event(guid)`,
		`CREATE INDEX IF NOT EXISTS idx_process_image ON process_event(image)`,
		`CREATE TABLE IF NOT EXISTS process_list(
			guid TEXT PRIMARY KEY,
			start_ts INTEGER DEFAULT 0,
			end_ts INTEGER DEFAULT 0,
			host TEXT, pid TEXT, image TEXT, cmdline TEXT, user TEXT,
			integrity TEXT, hashes TEXT, parent_guid TEXT, parent_pid TEXT,
			parent_image TEXT, parent_cmdline TEXT, rule_name TEXT, source TEXT,
			n INTEGER DEFAULT 0, pub INTEGER DEFAULT 0, ips INTEGER DEFAULT 0,
			first_ts INTEGER DEFAULT 0, last_ts INTEGER DEFAULT 0, risky INTEGER DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_process_list_start ON process_list(start_ts)`,
		`CREATE INDEX IF NOT EXISTS idx_process_list_start_guid
			ON process_list(start_ts DESC, guid ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_process_list_image ON process_list(image)`,
		`CREATE VIEW IF NOT EXISTS process_list_view AS
			SELECT guid,start_ts AS ts,end_ts,host,pid,image,cmdline,user,integrity,hashes,
				parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,source,
				n,pub,ips,first_ts,last_ts,risky
			FROM process_list`,
		`CREATE TABLE IF NOT EXISTS process_ip(
			guid TEXT NOT NULL, dst_ip TEXT NOT NULL,
			PRIMARY KEY(guid,dst_ip)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_process_ip_guid ON process_ip(guid)`,
		`CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY, value TEXT)`,
		`CREATE TABLE IF NOT EXISTS file(name TEXT PRIMARY KEY, events INTEGER, imported_at INTEGER, path TEXT, bytes INTEGER)`,
		`CREATE TABLE IF NOT EXISTS rawfield(name TEXT PRIMARY KEY, n INTEGER)`,
	}
	for _, s := range stmts {
		if _, err := d.sql.Exec(s); err != nil {
			return fmt.Errorf("%w: %s", err, s)
		}
	}
	for _, col := range []string{"path", "bytes"} {
		if !d.hasColumn("file", col) {
			if _, err := d.sql.Exec("ALTER TABLE file ADD COLUMN " + col + " " + map[string]string{"path": "TEXT", "bytes": "INTEGER"}[col]); err != nil {
				return err
			}
		}
	}
	dnsGeoUpgrade := false
	for _, spec := range []struct{ table, col, typ string }{
		{"conn", "source", "TEXT"},
		{"dns", "source", "TEXT"},
		{"dns", "geo", "TEXT"},
		{"dns", "country", "TEXT"},
		{"dns", "risk", "TEXT"},
	} {
		if !d.hasColumn(spec.table, spec.col) {
			if _, err := d.sql.Exec("ALTER TABLE " + spec.table + " ADD COLUMN " + spec.col + " " + spec.typ); err != nil {
				return err
			}
			if spec.table == "dns" && (spec.col == "geo" || spec.col == "country" || spec.col == "risk") {
				dnsGeoUpgrade = true
			}
		}
	}
	_, _ = d.sql.Exec(`CREATE INDEX IF NOT EXISTS idx_conn_source ON conn(source)`)
	_, _ = d.sql.Exec(`CREATE INDEX IF NOT EXISTS idx_dns_source ON dns(source)`)
	_, _ = d.sql.Exec(`CREATE INDEX IF NOT EXISTS idx_dns_geo ON dns(geo)`)
	_, _ = d.sql.Exec(`CREATE INDEX IF NOT EXISTS idx_dns_country ON dns(country)`)
	_, _ = d.sql.Exec(`CREATE INDEX IF NOT EXISTS idx_dns_risk ON dns(risk)`)
	if dnsGeoUpgrade {
		if err := d.backfillDNSGeoRisk(); err != nil {
			return fmt.Errorf("回填 DNS 归属地失败: %w", err)
		}
	}
	var dnsUniqueIndex int
	_ = d.sql.QueryRow(`SELECT count(*) FROM sqlite_master
		WHERE type='index' AND name='idx_dns_unique'`).Scan(&dnsUniqueIndex)
	if dnsUniqueIndex == 0 {
		_, _ = d.sql.Exec(`DELETE FROM dns WHERE id NOT IN (
			SELECT min(id) FROM dns
			GROUP BY ts,coalesce(host,''),coalesce(guid,''),coalesce(query,''),
				coalesce(results,''),coalesce(status,'')
		)`)
		if _, err := d.sql.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_unique ON dns(
			ts,coalesce(host,''),coalesce(guid,''),coalesce(query,''),
			coalesce(results,''),coalesce(status,'')
		)`); err != nil {
			return fmt.Errorf("创建 DNS 唯一索引失败: %w", err)
		}
	}
	var processListVersion string
	_ = d.sql.QueryRow(`SELECT value FROM app_meta WHERE key='process_list_version'`).Scan(&processListVersion)
	if processListVersion != "1" {
		if err := d.rebuildProcessList(); err != nil {
			return fmt.Errorf("初始化进程聚合表失败: %w", err)
		}
		_, _ = d.sql.Exec(`INSERT INTO app_meta(key,value) VALUES('process_list_version','1')
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`)
	}
	// 旧库只有单个导入文件时，把历史记录归到该文件，保证删除按钮可用。
	var importedFiles int
	_ = d.sql.QueryRow(`SELECT count(*) FROM file WHERE name != ?`, liveSource).Scan(&importedFiles)
	if importedFiles == 1 {
		var name string
		if err := d.sql.QueryRow(`SELECT name FROM file WHERE name != ? LIMIT 1`, liveSource).Scan(&name); err == nil {
			_, _ = d.sql.Exec(`UPDATE conn SET source=? WHERE source IS NULL OR source=''`, name)
			_, _ = d.sql.Exec(`UPDATE dns SET source=? WHERE source IS NULL OR source=''`, name)
		}
	}
	// 全文索引：trigram 支持子串匹配（ASCII 不区分大小写，中文需 >=3 个字）。
	if _, err := d.sql.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS conn_fts USING fts5(image, cmdline, dst_host, geo, dst_ip, content='', tokenize='trigram')`); err != nil {
		return err
	}
	if !d.hasColumn("conn_fts", "dst_ip") {
		appPrintf("升级全文索引：加入目的 IP 后重建")
		if err := d.rebuildFTS(); err != nil {
			return fmt.Errorf("重建全文索引失败: %w", err)
		}
	}
	return nil
}

func (d *DB) backfillDNSGeoRisk() error {
	type dnsGeoRow struct {
		id      int64
		results string
		status  string
	}
	rows, err := d.sql.Query(`SELECT id,coalesce(results,''),coalesce(status,'') FROM dns`)
	if err != nil {
		return err
	}
	items := []dnsGeoRow{}
	for rows.Next() {
		var item dnsGeoRow
		if err := rows.Scan(&item.id, &item.results, &item.status); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE dns SET geo=?,country=?,risk=? WHERE id=?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, item := range items {
		geo, country, risk := dnsGeoRisk(item.results, item.status, d.geo)
		if _, err := stmt.Exec(geo, country, risk, item.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) rebuildProcessList() error {
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`DELETE FROM process_ip`,
		`DELETE FROM process_list`,
		`INSERT INTO process_list(
			guid,start_ts,host,pid,image,cmdline,user,integrity,hashes,
			parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,source)
		SELECT guid,ts,host,pid,image,cmdline,user,integrity,hashes,
			parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,source
		FROM (
			SELECT *,row_number() OVER (PARTITION BY guid ORDER BY ts ASC) rn
			FROM process_event WHERE event_id=1 AND guid!=''
		) WHERE rn=1`,
		`INSERT OR IGNORE INTO process_list(guid)
			SELECT DISTINCT guid FROM process_event WHERE guid!=''`,
		`UPDATE process_list SET end_ts=coalesce(
			(SELECT max(ts) FROM process_event p
			 WHERE p.guid=process_list.guid AND p.event_id=5),end_ts)`,
		`INSERT OR IGNORE INTO process_list(guid)
			SELECT DISTINCT guid FROM conn WHERE guid!=''`,
		`INSERT OR IGNORE INTO process_ip(guid,dst_ip)
			SELECT DISTINCT guid,dst_ip FROM conn WHERE guid!='' AND dst_ip!=''`,
		`UPDATE process_list SET
			host=CASE WHEN coalesce(host,'')='' THEN coalesce(
				(SELECT host FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE host END,
			pid=CASE WHEN coalesce(pid,'')='' THEN coalesce(
				(SELECT pid FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE pid END,
			image=CASE WHEN coalesce(image,'')='' THEN coalesce(
				(SELECT image FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE image END,
			cmdline=CASE WHEN coalesce(cmdline,'')='' THEN coalesce(
				(SELECT cmdline FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE cmdline END,
			user=CASE WHEN coalesce(user,'')='' THEN coalesce(
				(SELECT user FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE user END,
			hashes=CASE WHEN coalesce(hashes,'')='' THEN coalesce(
				(SELECT hashes FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE hashes END,
			parent_image=CASE WHEN coalesce(parent_image,'')='' THEN coalesce(
				(SELECT parent FROM conn c WHERE c.guid=process_list.guid ORDER BY ts DESC LIMIT 1),'') ELSE parent_image END,
			n=(SELECT count(*) FROM conn c WHERE c.guid=process_list.guid),
			pub=(SELECT coalesce(sum(public),0) FROM conn c WHERE c.guid=process_list.guid),
			ips=(SELECT count(DISTINCT dst_ip) FROM conn c
				WHERE c.guid=process_list.guid AND dst_ip!=''),
			first_ts=(SELECT min(ts) FROM conn c WHERE c.guid=process_list.guid),
			last_ts=(SELECT max(ts) FROM conn c WHERE c.guid=process_list.guid),
			risky=(SELECT count(*) FROM conn c WHERE c.guid=process_list.guid AND risk!=''),
			source=coalesce((SELECT group_concat(DISTINCT NULLIF(source,'')) FROM conn c
				WHERE c.guid=process_list.guid),source)
		WHERE EXISTS(SELECT 1 FROM conn c WHERE c.guid=process_list.guid)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("%w: %s", err, stmt)
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- 导入

type ImportStats struct {
	Files  []string `json:"files"`
	Events int      `json:"events"`
	Conns  int      `json:"conns"`
	DNS    int      `json:"dns"`
	Took   string   `json:"took"`
}

func (d *DB) Import(paths []string) (ImportStats, error) {
	start := time.Now()
	files, err := expandPaths(paths)
	if err != nil {
		return ImportStats{}, err
	}
	if len(files) == 0 {
		return ImportStats{}, fmt.Errorf("没有找到 .evtx 文件")
	}

	stats := ImportStats{Files: []string{}}
	for _, f := range files {
		evs, err := readEvtxFile(f)
		if err != nil {
			return stats, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		n, dn, err := d.Ingest(evs, filepath.Base(f))
		if err != nil {
			return stats, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		stats.Events += len(evs)
		stats.Conns += n
		stats.DNS += dn
		name := filepath.Base(f)
		if fi, err := os.Stat(f); err == nil {
			abs := f
			if a, err := filepath.Abs(f); err == nil {
				abs = a
			}
			d.SetFileInfo(name, abs, fi.Size())
		}
		stats.Files = append(stats.Files, name)
	}
	stats.Took = time.Since(start).Round(time.Millisecond).String()
	return stats, nil
}

// SetFileInfo 记录源文件的完整路径与大小（浏览器上传时 path 传空）。
func (d *DB) SetFileInfo(name, path string, size int64) error {
	_, err := d.sql.Exec(`UPDATE file SET path=?, bytes=? WHERE name=?`, path, size, name)
	return err
}

func (d *DB) hasColumn(table, col string) bool {
	rows, err := d.sql.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == col {
			return true
		}
	}
	return false
}

// Ingest 处理一批事件并入库；实时采集与离线导入共用。
// src 为空表示实时数据（不写入文件清单）。
func (d *DB) Ingest(evs []rawEvent, src string) (int, int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var conns []*Conn
	var dnss []*DNSQ
	var procs []*ProcessEvent
	rawKeys := map[string]int{}

	for i := range evs {
		e := &evs[i]
		switch e.EID {
		case "1":
			g := e.get("ProcessGuid")
			if g == "" {
				continue
			}
			if pe := processEventFromRaw(e); pe != nil {
				procs = append(procs, pe)
			}
			d.procCache[g] = &procInfo{Image: e.get("Image"), CmdLine: e.get("CommandLine"), Parent: e.get("ParentImage"), Hashes: e.get("Hashes"), User: e.get("User"), Integ: e.get("IntegrityLevel")}
		case "5":
			if pe := processEventFromRaw(e); pe != nil {
				procs = append(procs, pe)
			}
		case "3":
			c := connFromEvent(e, d.geo)
			if c == nil {
				continue
			}
			c.Raw = e.F
			for k := range e.F {
				rawKeys[k]++
			}
			conns = append(conns, c)
		case "22":
			q := dnsFromEvent(e)
			if q == nil {
				continue
			}
			q.Raw = e.F
			geo, country, risk := dnsGeoRisk(q.Results, q.Status, d.geo)
			q.Geo, q.Country, q.Risk = geo, country, strings.Fields(risk)
			for k := range e.F {
				rawKeys[k]++
			}
			dnss = append(dnss, q)
			for _, ip := range dnsIPs(q.Results) {
				l := append(d.ipdns[ip], ipDNS{ts: q.TS, domain: q.Query})
				if len(l) > 32 {
					l = l[len(l)-32:]
				}
				d.ipdns[ip] = l
			}
		}
	}

	for _, c := range conns {
		if p, ok := d.procCache[c.Guid]; ok {
			if c.Image == "" {
				c.Image = p.Image
			}
			c.CmdLine, c.Parent, c.Hashes, c.Integ = p.CmdLine, p.Parent, p.Hashes, p.Integ
			if c.User == "" {
				c.User = p.User
			}
		}
		if c.DstHost == "" {
			if l := d.ipdns[c.DstIP]; len(l) > 0 {
				c.DstHost = nearestDomain(l, c.TS)
			}
		}
		c.Risk = judge(c)
	}
	markFanout(conns)

	n, err := d.writeBatch(src, conns, dnss, procs, rawKeys, len(evs), strings.HasPrefix(src, liveSource))
	if err != nil {
		return 0, 0, err
	}
	return n, len(dnss), nil
}

// Warmup 只填充进程与 IP->域名缓存，不写库，避免启动时重复写入历史事件。
func (d *DB) Warmup(evs []rawEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range evs {
		e := &evs[i]
		switch e.EID {
		case "1":
			g := e.get("ProcessGuid")
			if g == "" {
				continue
			}
			d.procCache[g] = &procInfo{Image: e.get("Image"), CmdLine: e.get("CommandLine"), Parent: e.get("ParentImage"), Hashes: e.get("Hashes"), User: e.get("User"), Integ: e.get("IntegrityLevel")}
		case "22":
			q := dnsFromEvent(e)
			if q == nil {
				continue
			}
			for _, ip := range dnsIPs(q.Results) {
				l := append(d.ipdns[ip], ipDNS{ts: q.TS, domain: q.Query})
				if len(l) > 32 {
					l = l[len(l)-32:]
				}
				d.ipdns[ip] = l
			}
		}
	}
}

func (d *DB) writeBatch(file string, conns []*Conn, dnss []*DNSQ, procs []*ProcessEvent, rawKeys map[string]int, events int, merge bool) (int, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	insConn, err := tx.Prepare(`INSERT OR IGNORE INTO conn(ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk,raw,source)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insConn.Close()
	insFTS, err := tx.Prepare(`INSERT INTO conn_fts(rowid,image,cmdline,dst_host,geo,dst_ip) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insFTS.Close()

	n := 0
	for _, c := range conns {
		raw, _ := json.Marshal(c.Raw)
		res, err := insConn.Exec(c.TS, c.Host, c.PID, c.Guid, c.Image, c.User, c.Proto, c.SrcIP, c.SrcPort, c.DstIP, atoi(c.DstPort), c.DstHost, c.PortNm, b2i(c.Out), b2i(c.V6), c.Geo, b2i(c.Public), c.CmdLine, c.Parent, c.Hashes, c.Integ, c.Rule, strings.Join(c.Risk, " "), string(raw), file)
		if err != nil {
			return n, err
		}
		if aff, _ := res.RowsAffected(); aff == 0 {
			continue
		}
		id, _ := res.LastInsertId()
		n++
		if _, err := insFTS.Exec(id, c.Image, c.CmdLine, c.DstHost, c.Geo, c.DstIP); err != nil {
			return n, err
		}
		if err := updateProcessListFromConn(tx, c, file); err != nil {
			return n, err
		}
	}

	if len(dnss) > 0 {
		insDNS, err := tx.Prepare(`INSERT OR IGNORE INTO dns(ts,host,pid,guid,image,user,query,results,status,geo,country,risk,raw,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return n, err
		}
		defer insDNS.Close()
		for _, q := range dnss {
			raw, _ := json.Marshal(q.Raw)
			if _, err := insDNS.Exec(q.TS, q.Host, q.PID, q.Guid, q.Image, q.User, q.Query,
				q.Results, q.Status, q.Geo, q.Country, strings.Join(q.Risk, " "), string(raw), file); err != nil {
				return n, err
			}
		}
	}

	if len(procs) > 0 {
		insProc, err := tx.Prepare(`INSERT OR IGNORE INTO process_event(
			event_id,ts,host,guid,pid,image,cmdline,user,integrity,hashes,
			parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,raw,source)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return n, err
		}
		defer insProc.Close()
		for _, p := range procs {
			raw, _ := json.Marshal(p.Raw)
			if _, err := insProc.Exec(p.EventID, p.TS, p.Host, p.Guid, p.PID, p.Image,
				p.CmdLine, p.User, p.Integrity, p.Hashes, p.ParentGuid, p.ParentPID,
				p.ParentImage, p.ParentCmdLine, p.Rule, string(raw), file); err != nil {
				return n, err
			}
			if err := updateProcessListFromEvent(tx, p, file); err != nil {
				return n, err
			}
		}
	}

	upsert := `INSERT INTO file(name,events,imported_at) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET events=excluded.events, imported_at=excluded.imported_at`
	if merge { // 实时采集按批次累加事件数
		upsert = `INSERT INTO file(name,events,imported_at) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET events=file.events+excluded.events, imported_at=excluded.imported_at`
	}
	if _, err := tx.Exec(upsert, file, events, time.Now().Unix()); err != nil {
		return n, err
	}
	for k, v := range rawKeys {
		if _, err := tx.Exec(`INSERT INTO rawfield(name,n) VALUES(?,?)
			ON CONFLICT(name) DO UPDATE SET n=n+excluded.n`, k, v); err != nil {
			return n, err
		}
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

func updateProcessListFromEvent(tx *sql.Tx, p *ProcessEvent, source string) error {
	if p == nil || p.Guid == "" {
		return nil
	}
	startTS, endTS := int64(0), int64(0)
	switch p.EventID {
	case 1:
		startTS = p.TS
	case 5:
		endTS = p.TS
	}
	_, err := tx.Exec(`INSERT INTO process_list(
		guid,start_ts,end_ts,host,pid,image,cmdline,user,integrity,hashes,
		parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,source)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(guid) DO UPDATE SET
			start_ts=CASE
				WHEN excluded.start_ts>0 AND (process_list.start_ts=0 OR excluded.start_ts<process_list.start_ts)
				THEN excluded.start_ts ELSE process_list.start_ts END,
			end_ts=max(process_list.end_ts,excluded.end_ts),
			host=CASE WHEN excluded.host!='' THEN excluded.host ELSE process_list.host END,
			pid=CASE WHEN excluded.pid!='' THEN excluded.pid ELSE process_list.pid END,
			image=CASE WHEN excluded.image!='' THEN excluded.image ELSE process_list.image END,
			cmdline=CASE WHEN excluded.cmdline!='' THEN excluded.cmdline ELSE process_list.cmdline END,
			user=CASE WHEN excluded.user!='' THEN excluded.user ELSE process_list.user END,
			integrity=CASE WHEN excluded.integrity!='' THEN excluded.integrity ELSE process_list.integrity END,
			hashes=CASE WHEN excluded.hashes!='' THEN excluded.hashes ELSE process_list.hashes END,
			parent_guid=CASE WHEN excluded.parent_guid!='' THEN excluded.parent_guid ELSE process_list.parent_guid END,
			parent_pid=CASE WHEN excluded.parent_pid!='' THEN excluded.parent_pid ELSE process_list.parent_pid END,
			parent_image=CASE WHEN excluded.parent_image!='' THEN excluded.parent_image ELSE process_list.parent_image END,
			parent_cmdline=CASE WHEN excluded.parent_cmdline!='' THEN excluded.parent_cmdline ELSE process_list.parent_cmdline END,
			rule_name=CASE WHEN excluded.rule_name!='' THEN excluded.rule_name ELSE process_list.rule_name END,
			source=CASE
				WHEN coalesce(process_list.source,'')='' THEN excluded.source
				WHEN coalesce(excluded.source,'')='' OR process_list.source=excluded.source
					OR instr(process_list.source,excluded.source)>0 THEN process_list.source
				ELSE process_list.source || ',' || excluded.source END`,
		p.Guid, startTS, endTS, p.Host, p.PID, p.Image, p.CmdLine, p.User,
		p.Integrity, p.Hashes, p.ParentGuid, p.ParentPID, p.ParentImage,
		p.ParentCmdLine, p.Rule, source)
	return err
}

func updateProcessListFromConn(tx *sql.Tx, c *Conn, source string) error {
	if c == nil || c.Guid == "" {
		return nil
	}
	ipsDelta := 0
	if c.DstIP != "" {
		res, err := tx.Exec(`INSERT OR IGNORE INTO process_ip(guid,dst_ip) VALUES(?,?)`, c.Guid, c.DstIP)
		if err != nil {
			return err
		}
		if aff, _ := res.RowsAffected(); aff > 0 {
			ipsDelta = 1
		}
	}
	risky := 0
	if len(c.Risk) > 0 {
		risky = 1
	}
	_, err := tx.Exec(`INSERT INTO process_list(
		guid,host,pid,image,cmdline,user,parent_image,hashes,source,
		n,pub,ips,first_ts,last_ts,risky)
		VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)
		ON CONFLICT(guid) DO UPDATE SET
			host=CASE WHEN coalesce(process_list.host,'')='' THEN excluded.host ELSE process_list.host END,
			pid=CASE WHEN excluded.pid!='' AND excluded.last_ts>=process_list.last_ts
				THEN excluded.pid ELSE process_list.pid END,
			image=CASE WHEN coalesce(process_list.image,'')='' THEN excluded.image ELSE process_list.image END,
			cmdline=CASE WHEN coalesce(process_list.cmdline,'')='' THEN excluded.cmdline ELSE process_list.cmdline END,
			user=CASE WHEN coalesce(process_list.user,'')='' THEN excluded.user ELSE process_list.user END,
			parent_image=CASE WHEN coalesce(process_list.parent_image,'')='' THEN excluded.parent_image ELSE process_list.parent_image END,
			hashes=CASE WHEN coalesce(process_list.hashes,'')='' THEN excluded.hashes ELSE process_list.hashes END,
			n=process_list.n+1,
			pub=process_list.pub+excluded.pub,
			ips=process_list.ips+excluded.ips,
			first_ts=CASE WHEN process_list.first_ts=0 OR excluded.first_ts<process_list.first_ts
				THEN excluded.first_ts ELSE process_list.first_ts END,
			last_ts=max(process_list.last_ts,excluded.last_ts),
			risky=process_list.risky+excluded.risky,
			source=CASE
				WHEN coalesce(process_list.source,'')='' THEN excluded.source
				WHEN coalesce(excluded.source,'')='' OR process_list.source=excluded.source
					OR instr(process_list.source,excluded.source)>0 THEN process_list.source
				ELSE process_list.source || ',' || excluded.source END`,
		c.Guid, c.Host, c.PID, c.Image, c.CmdLine, c.User, c.Parent, c.Hashes, source,
		b2i(c.Public), ipsDelta, c.TS, c.TS, risky)
	return err
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- 查询语法

// compile 把查询表达式编译成 SQL。
// 语法：AND 必须显式书写，| 或 OR=OR，- 或 NOT=取反，括号可分组。
// 优先级：NOT > AND > OR。
func (d *DB) compile(expr string) (string, []interface{}, error) {
	toks := tokenize(expr)
	if len(toks) == 0 {
		return "1=1", nil, nil
	}
	p := &parser{toks: toks, condFn: d.cond}
	cond, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	if p.pos < len(p.toks) {
		return "", nil, fmt.Errorf("语法错误：多余的内容 %q", p.toks[p.pos])
	}
	return cond, p.args, nil
}

// compileDNS 把 DNS 页的筛选语法编译为 dns 表查询条件。
func (d *DB) compileDNS(expr string) (string, []interface{}, error) {
	toks := tokenize(expr)
	if len(toks) == 0 {
		return "1=1", nil, nil
	}
	p := &parser{toks: toks, condFn: d.dnsCond}
	cond, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	if p.pos < len(p.toks) {
		return "", nil, fmt.Errorf("语法错误：多余的内容 %q", p.toks[p.pos])
	}
	return cond, p.args, nil
}

func (d *DB) compileProcess(expr string) (string, []interface{}, error) {
	toks := tokenize(expr)
	if len(toks) == 0 {
		return "1=1", nil, nil
	}
	p := &parser{toks: toks, condFn: d.processCond}
	cond, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	if p.pos < len(p.toks) {
		return "", nil, fmt.Errorf("语法错误：多余的内容 %q", p.toks[p.pos])
	}
	return cond, p.args, nil
}

type parser struct {
	toks   []string
	pos    int
	condFn func(string) (string, []interface{}, error)
	args   []interface{}
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func isOr(t string) bool {
	switch strings.ToLower(t) {
	case "|", "||", "or", "或":
		return true
	}
	return false
}

func isAnd(t string) bool {
	switch strings.ToLower(t) {
	case "and", "且", "&&":
		return true
	}
	return false
}

func (p *parser) parseOr() (string, error) {
	left, err := p.parseAnd()
	if err != nil {
		return "", err
	}
	var parts []string
	parts = append(parts, left)
	for isOr(p.peek()) {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return "", err
		}
		parts = append(parts, right)
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

func (p *parser) parseAnd() (string, error) {
	if isAnd(p.peek()) {
		return "", fmt.Errorf("语法错误：AND 前缺少条件")
	}
	first, err := p.parseUnary()
	if err != nil {
		return "", err
	}
	parts := []string{first}
	for {
		t := p.peek()
		if t == "" || t == ")" || isOr(t) {
			break
		}
		if !isAnd(t) {
			return "", fmt.Errorf("语法错误：条件之间必须显式使用 AND（位置 %q）", t)
		}
		p.pos++
		c, err := p.parseUnary()
		if err != nil {
			return "", err
		}
		parts = append(parts, c)
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " AND ") + ")", nil
}

func (p *parser) parseUnary() (string, error) {
	t := p.peek()
	if t == "" {
		return "", fmt.Errorf("语法错误：条件不完整")
	}
	if t == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return "", err
		}
		if p.peek() != ")" {
			return "", fmt.Errorf("语法错误：缺少右括号")
		}
		p.pos++
		return "(" + inner + ")", nil
	}
	neg := false
	if t == "-" || strings.EqualFold(t, "not") || t == "非" {
		neg, p.pos = true, p.pos+1
		t = p.peek()
		if t == "" || t == ")" || isOr(t) {
			return "", fmt.Errorf("语法错误：取反后缺少条件")
		}
	}
	if strings.HasPrefix(t, "-") && len(t) > 1 {
		neg, t = true, t[1:]
	}
	if t == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return "", err
		}
		if p.peek() != ")" {
			return "", fmt.Errorf("语法错误：缺少右括号")
		}
		p.pos++
		if neg {
			return "NOT (" + inner + ")", nil
		}
		return "(" + inner + ")", nil
	}
	p.pos++
	c, a, err := p.condFn(t)
	if err != nil {
		return "", err
	}
	p.args = append(p.args, a...)
	if c == "" {
		return "1=1", nil
	}
	if neg {
		return "NOT (" + c + ")", nil
	}
	return c, nil
}

// tokenize 按空格切分，双引号内视为整体，括号和 | 单独成词。
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case inQ:
			cur.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		case r == '(' || r == ')':
			flush()
			out = append(out, string(r))
		case r == '|':
			flush()
			out = append(out, "|")
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func (d *DB) cond(tok string) (string, []interface{}, error) {
	op, idx := findOp(tok)
	if idx < 0 {
		return d.textCond(tok)
	}
	field := strings.TrimSpace(tok[:idx])
	val := strings.Trim(strings.TrimSpace(tok[idx+len(op):]), `"`)
	if field == "" || val == "" {
		return "", nil, nil
	}
	col, meta, err := d.resolve(field)
	if err != nil {
		return "", nil, err
	}

	if meta.Type == "bool" {
		val = normBool(val)
	}
	if meta.Type == "time" {
		if ms, ok := parseTimeValue(val); ok {
			val = strconv.FormatInt(ms, 10)
		}
	}

	switch op {
	case ":":
		// 冒号表示"包含"，符合直觉：geo:北京 能匹配 "北京市 联通"。
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	case "!:":
		if meta.Type != "text" {
			return "", nil, fmt.Errorf("不包含仅适用于文本字段")
		}
		if strings.Contains(val, "*") {
			return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{"%" + val + "%"}, nil
	case "=":
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " = ?", []interface{}{val}, nil
	case "!=":
		return "(" + col + " IS NULL OR " + col + " != ?)", []interface{}{val}, nil
	case "~":
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	default:
		e := col
		if meta.Type == "int" || meta.Type == "time" || meta.Type == "bool" {
			e = "CAST(" + col + " AS INTEGER)"
		}
		return e + " " + op + " ?", []interface{}{val}, nil
	}
}

func (d *DB) dnsCond(tok string) (string, []interface{}, error) {
	op, idx := findOp(tok)
	if idx < 0 {
		return d.dnsTextCond(tok)
	}
	field := strings.TrimSpace(tok[:idx])
	val := strings.Trim(strings.TrimSpace(tok[idx+len(op):]), `"`)
	if field == "" || val == "" {
		return "", nil, nil
	}
	col, typ, err := dnsField(field)
	if err != nil {
		return "", nil, err
	}
	if typ == "time" {
		if ms, ok := parseTimeValue(val); ok {
			val = strconv.FormatInt(ms, 10)
		}
	}
	switch op {
	case ":":
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	case "!:":
		if typ != "text" {
			return "", nil, fmt.Errorf("不包含仅适用于文本字段")
		}
		if strings.Contains(val, "*") {
			return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{"%" + val + "%"}, nil
	case "=":
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " = ?", []interface{}{val}, nil
	case "!=":
		return "(" + col + " IS NULL OR " + col + " != ?)", []interface{}{val}, nil
	case "~":
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	default:
		expr := col
		if typ == "int" || typ == "time" {
			expr = "CAST(" + col + " AS INTEGER)"
		}
		return expr + " " + op + " ?", []interface{}{val}, nil
	}
}

func dnsField(name string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ts", "时间", "time":
		return "ts", "time", nil
	case "host", "主机":
		return "host", "text", nil
	case "pid":
		return "pid", "text", nil
	case "guid", "进程guid":
		return "guid", "text", nil
	case "image", "进程":
		return "image", "text", nil
	case "user", "用户":
		return "user", "text", nil
	case "query", "queryname", "域名", "查询域名", "dst_host":
		return "query", "text", nil
	case "results", "queryresults", "解析结果", "dst_ip":
		return "results", "text", nil
	case "status", "querystatus", "状态":
		return "status", "int", nil
	case "geo", "归属地":
		return "geo", "text", nil
	case "country", "国家", "国家地区":
		return "country", "text", nil
	case "risk", "风险":
		return "risk", "text", nil
	case "rule", "rule_name", "rulename", "规则":
		return "json_extract(raw,'$.RuleName')", "text", nil
	}
	return "", "", fmt.Errorf("DNS 不支持字段: %s", name)
}

func (d *DB) dnsTextCond(q string) (string, []interface{}, error) {
	l := "%" + strings.ReplaceAll(q, "*", "%") + "%"
	return `(query LIKE ? OR image LIKE ? OR results LIKE ? OR user LIKE ?
		OR host LIKE ? OR pid LIKE ? OR guid LIKE ? OR source LIKE ?
		OR geo LIKE ? OR country LIKE ? OR risk LIKE ?
		OR coalesce(json_extract(raw,'$.RuleName'),'') LIKE ?)`,
		[]interface{}{l, l, l, l, l, l, l, l, l, l, l, l}, nil
}

func (d *DB) processCond(tok string) (string, []interface{}, error) {
	op, idx := findOp(tok)
	if idx < 0 {
		l := "%" + strings.ReplaceAll(tok, "*", "%") + "%"
		return `(image LIKE ? OR cmdline LIKE ? OR user LIKE ? OR parent_image LIKE ?
			OR parent_cmdline LIKE ? OR hashes LIKE ? OR rule_name LIKE ?
			OR host LIKE ? OR pid LIKE ? OR guid LIKE ? OR parent_guid LIKE ?
			OR parent_pid LIKE ? OR integrity LIKE ? OR source LIKE ?)`,
			[]interface{}{l, l, l, l, l, l, l, l, l, l, l, l, l, l}, nil
	}
	field := strings.TrimSpace(tok[:idx])
	val := strings.Trim(strings.TrimSpace(tok[idx+len(op):]), `"`)
	if field == "" || val == "" {
		return "", nil, nil
	}
	col, typ, err := processField(field)
	if err != nil {
		return "", nil, err
	}
	if typ == "time" {
		if ms, ok := parseTimeValue(val); ok {
			val = strconv.FormatInt(ms, 10)
		}
	}
	switch op {
	case ":":
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	case "!:":
		if typ != "text" {
			return "", nil, fmt.Errorf("不包含仅适用于文本字段")
		}
		if strings.Contains(val, "*") {
			return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return "(" + col + " IS NULL OR " + col + " NOT LIKE ?)", []interface{}{"%" + val + "%"}, nil
	case "=":
		if strings.Contains(val, "*") {
			return col + " LIKE ?", []interface{}{strings.ReplaceAll(val, "*", "%")}, nil
		}
		return col + " = ?", []interface{}{val}, nil
	case "!=":
		return "(" + col + " IS NULL OR " + col + " != ?)", []interface{}{val}, nil
	case "~":
		return col + " LIKE ?", []interface{}{"%" + val + "%"}, nil
	default:
		expr := col
		if typ == "int" || typ == "time" {
			expr = "CAST(" + col + " AS INTEGER)"
		}
		return expr + " " + op + " ?", []interface{}{val}, nil
	}
}

func processField(name string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ts", "时间", "time":
		return "ts", "time", nil
	case "host", "主机":
		return "host", "text", nil
	case "pid":
		return "pid", "text", nil
	case "guid", "进程guid":
		return "guid", "text", nil
	case "image", "进程":
		return "image", "text", nil
	case "cmdline", "命令行":
		return "cmdline", "text", nil
	case "user", "用户":
		return "user", "text", nil
	case "integrity", "完整性":
		return "integrity", "text", nil
	case "hashes", "哈希":
		return "hashes", "text", nil
	case "parent", "parent_image", "父进程":
		return "parent_image", "text", nil
	case "parent_guid", "父进程guid":
		return "parent_guid", "text", nil
	case "parent_pid", "父pid":
		return "parent_pid", "text", nil
	case "parent_cmdline", "父命令行":
		return "parent_cmdline", "text", nil
	case "rule", "rule_name", "rulename", "规则":
		return "rule_name", "text", nil
	case "source", "来源":
		return "source", "text", nil
	case "event_id", "事件id":
		return "event_id", "int", nil
	}
	return "", "", fmt.Errorf("进程不支持字段: %s", name)
}

func findOp(tok string) (string, int) {
	bestOp, bestIdx := "", -1
	for _, op := range []string{"!=", "!:", ">=", "<=", ":", "=", "~", ">", "<"} {
		i := strings.Index(tok, op)
		if i <= 0 {
			continue
		}
		if bestIdx < 0 || i < bestIdx || (i == bestIdx && len(op) > len(bestOp)) {
			bestOp, bestIdx = op, i
		}
	}
	return bestOp, bestIdx
}

func normBool(v string) string {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "出站", "out", "外向":
		return "1"
	case "0", "false", "no", "n", "入站", "in", "内向":
		return "0"
	}
	return v
}

func parseTimeValue(s string) (int64, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixMilli(), true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	return 0, false
}

// resolve 把字段名解析成 SQL 列表达式（带白名单校验）。
func (d *DB) resolve(name string) (string, FieldMeta, error) {
	if m, ok := promotedIdx[name]; ok {
		return name, m, nil
	}
	alias := map[string]string{
		"时间": "ts", "进程": "image", "命令行": "cmdline", "用户": "user",
		"目的ip": "dst_ip", "目的IP": "dst_ip", "源ip": "src_ip", "源IP": "src_ip",
		"端口": "dst_port", "域名": "dst_host", "归属地": "geo", "协议": "proto",
	}
	if c, ok := alias[name]; ok {
		return d.resolve(c)
	}
	if safeName.MatchString(name) && d.hasRawField(name) {
		return "json_extract(raw,'$." + name + "')", FieldMeta{Name: name, Label: name, Type: "text", Raw: true}, nil
	}
	return "", FieldMeta{}, fmt.Errorf("未知字段: %s", name)
}

func (d *DB) hasRawField(name string) bool {
	var n int
	return d.sql.QueryRow(`SELECT n FROM rawfield WHERE name=?`, name).Scan(&n) == nil
}

// textCond 全文检索：>=3 个字符走 FTS5 trigram（含目的 IP），过短退化为 LIKE。
func (d *DB) textCond(q string) (string, []interface{}, error) {
	if len([]rune(q)) >= 3 {
		match := `"` + strings.ReplaceAll(q, `"`, "") + `"`
		return "conn.id IN (SELECT rowid FROM conn_fts WHERE conn_fts MATCH ?)", []interface{}{match}, nil
	}
	like := "%" + q + "%"
	return "(image LIKE ? OR cmdline LIKE ? OR dst_host LIKE ? OR geo LIKE ? OR dst_ip LIKE ?)",
		[]interface{}{like, like, like, like, like}, nil
}

func (d *DB) orderClause(sortField string, desc bool) (string, error) {
	order := "ts DESC, id DESC"
	if sortField != "" {
		col, _, err := d.resolve(sortField)
		if err != nil {
			return "", err
		}
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		order = col + " " + dir + ", ts DESC, id DESC"
	}
	return order, nil
}

// Count 只统计符合条件的行数，供原生界面刷新总数。
func (d *DB) Count(expr string) (int, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return 0, err
	}
	var total int
	err = d.sql.QueryRow("SELECT count(*) FROM conn WHERE "+where, args...).Scan(&total)
	return total, err
}

func (d *DB) SnapshotMaxID(expr string) (int64, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return 0, err
	}
	var id int64
	err = d.sql.QueryRow("SELECT coalesce(max(id),0) FROM conn WHERE "+where, args...).Scan(&id)
	return id, err
}

func (d *DB) CountBefore(expr string, maxID int64) (int, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return 0, err
	}
	args = append(args, maxID)
	var total int
	err = d.sql.QueryRow("SELECT count(*) FROM conn WHERE ("+where+") AND id<=?", args...).Scan(&total)
	return total, err
}

func (d *DB) CountProcesses() (int, error) {
	return d.CountProcessesFiltered("")
}

func (d *DB) CountProcessesFiltered(expr string) (int, error) {
	return d.CountProcessesFilteredAsOf(expr, 0)
}

func (d *DB) CountProcessesFilteredAsOf(expr string, asOf int64) (int, error) {
	where, args, err := d.compileProcess(expr)
	if err != nil {
		return 0, err
	}
	if asOf > 0 {
		where = "(" + where + ") AND ts<=?"
		args = append(args, asOf)
	}
	var total int
	err = d.sql.QueryRow("SELECT count(*) FROM process_list_view WHERE "+where, args...).Scan(&total)
	return total, err
}

func (d *DB) CountDNS() (int, error) {
	return d.CountDNSFiltered("")
}

func (d *DB) CountDNSFiltered(expr string) (int, error) {
	return d.CountDNSFilteredAsOf(expr, 0)
}

func (d *DB) CountDNSFilteredAsOf(expr string, asOf int64) (int, error) {
	where, args, err := d.compileDNS(expr)
	if err != nil {
		return 0, err
	}
	if asOf > 0 {
		where = "(" + where + ") AND ts<=?"
		args = append(args, asOf)
	}
	var total int
	err = d.sql.QueryRow("SELECT count(*) FROM dns WHERE "+where, args...).Scan(&total)
	return total, err
}

type LogTotals struct {
	Connections int
	Processes   int
	DNS         int
}

func (d *DB) LogTotals() (*LogTotals, error) {
	totals := &LogTotals{}
	if err := d.sql.QueryRow(`SELECT
		(SELECT count(*) FROM conn),
		(SELECT count(*) FROM dns)`).
		Scan(&totals.Connections, &totals.DNS); err != nil {
		return nil, err
	}
	processes, err := d.CountProcesses()
	if err != nil {
		return nil, err
	}
	totals.Processes = processes
	return totals, nil
}

// Page 取一页完整记录（含 raw JSON），供网页接口使用。
func (d *DB) Page(expr string, limit, offset int, sortField string, desc bool) ([]*Conn, error) {
	return d.queryPage(expr, limit, offset, sortField, desc, true)
}

// QueryLite 取一页轻量记录（不含 raw JSON），供原生表格缓存使用。
func (d *DB) QueryLite(expr string, limit, offset int, sortField string, desc bool) ([]*Conn, error) {
	return d.queryPage(expr, limit, offset, sortField, desc, false)
}

func (d *DB) QueryLiteBefore(expr string, limit, offset int, sortField string, desc bool, maxID int64) ([]*Conn, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, err
	}
	order, err := d.orderClause(sortField, desc)
	if err != nil {
		return nil, err
	}
	args = append(args, maxID, limit, offset)
	q := "SELECT " + connColsNoRaw + " FROM conn WHERE (" + where +
		") AND id<=? ORDER BY " + order + " LIMIT ? OFFSET ?"
	rows, err := d.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Conn, 0, limit)
	for rows.Next() {
		c, err := scanConnWithRaw(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) queryPage(expr string, limit, offset int, sortField string, desc, withRaw bool) ([]*Conn, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, err
	}
	order, err := d.orderClause(sortField, desc)
	if err != nil {
		return nil, err
	}
	cols := connCols
	if !withRaw {
		cols = connColsNoRaw
	}
	q := "SELECT " + cols + " FROM conn WHERE " +
		where + " ORDER BY " + order + " LIMIT ? OFFSET ?"
	rows, err := d.sql.Query(q, append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Conn, 0, limit)
	for rows.Next() {
		c, err := scanConnWithRaw(rows, withRaw)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Query 执行查询，返回分页结果与总数。
func (d *DB) Query(expr string, limit, offset int, sortField string, desc bool) ([]*Conn, int, error) {
	total, err := d.Count(expr)
	if err != nil {
		return nil, 0, err
	}
	rows, err := d.Page(expr, limit, offset, sortField, desc)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// ConnByID 读取单条完整连接，用于原生详情窗口。
func (d *DB) ConnByID(id int64) (*Conn, error) {
	row := d.sql.QueryRow("SELECT "+connCols+" FROM conn WHERE id = ?", id)
	return scanConn(row)
}

type scanner interface{ Scan(...interface{}) error }

func scanConn(rows scanner) (*Conn, error) {
	return scanConnWithRaw(rows, true)
}

// connCols 是 scanConn 读取的完整列；connColsNoRaw 用于导出，省掉 raw JSON。
const connCols = "id,ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk,raw,source"

const connColsNoRaw = "id,ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk,source"

func scanConnWithRaw(rows scanner, withRaw bool) (*Conn, error) {
	c := &Conn{}
	var out, v6, pub int
	var risk string
	if withRaw {
		var raw []byte
		if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.PID, &c.Guid, &c.Image, &c.User, &c.Proto, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort, &c.DstHost, &c.PortNm, &out, &v6, &c.Geo, &pub, &c.CmdLine, &c.Parent, &c.Hashes, &c.Integ, &c.Rule, &risk, &raw, &c.Source); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			var m map[string]string
			if json.Unmarshal(raw, &m) == nil {
				c.Raw = m
			}
		}
	} else if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.PID, &c.Guid, &c.Image, &c.User, &c.Proto, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort, &c.DstHost, &c.PortNm, &out, &v6, &c.Geo, &pub, &c.CmdLine, &c.Parent, &c.Hashes, &c.Integ, &c.Rule, &risk, &c.Source); err != nil {
		return nil, err
	}
	c.Out, c.V6, c.Public = out == 1, v6 == 1, pub == 1
	if risk != "" {
		c.Risk = strings.Fields(risk)
	}
	return c, nil
}

// ExportRows 编译检索条件并返回按时间倒序的游标，供导出边读边写。
// 不做 count(*)，也不加载 raw 字段，避免大结果集占满内存。
func (d *DB) ExportRows(expr string) (*sql.Rows, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, err
	}
	return d.sql.Query("SELECT "+connColsNoRaw+" FROM conn WHERE "+where+" ORDER BY ts DESC", args...)
}

// ---------------------------------------------------------------- 聚合

type Count struct {
	Key string `json:"key"`
	N   int    `json:"n"`
	Sub string `json:"sub,omitempty"`
}

type Bucket struct {
	T int64 `json:"t"`
	N int   `json:"n"`
}

type Summary struct {
	Conns     int      `json:"conns"`
	DNS       int      `json:"dns"`
	Public    int      `json:"public"`
	Private   int      `json:"private"`
	Outbound  int      `json:"outbound"`
	Processes int      `json:"processes"`
	DstIPs    int      `json:"dstIps"`
	Domains   int      `json:"domains"`
	From      int64    `json:"from"`
	To        int64    `json:"to"`
	Step      int64    `json:"step"`
	TopProc   []Count  `json:"topProc"`
	TopPort   []Count  `json:"topPort"`
	TopGeo    []Count  `json:"topGeo"`
	TopDst    []Count  `json:"topDst"`
	Timeline  []Bucket `json:"timeline"`
	Rules     []Count  `json:"rules"`
	Files     []string `json:"files"`
}

func (d *DB) Summary() (*Summary, error) {
	sm := &Summary{}
	var mn, mx sql.NullInt64
	d.sql.QueryRow("SELECT min(ts) FROM conn").Scan(&mn)
	d.sql.QueryRow("SELECT max(ts) FROM conn").Scan(&mx)
	sm.From, sm.To = mn.Int64, mx.Int64

	d.sql.QueryRow("SELECT count(*), coalesce(sum(public),0), coalesce(sum(1-public),0), coalesce(sum(outbound),0), count(DISTINCT image), count(DISTINCT dst_ip), count(DISTINCT NULLIF(dst_host,'')) FROM conn").
		Scan(&sm.Conns, &sm.Public, &sm.Private, &sm.Outbound, &sm.Processes, &sm.DstIPs, &sm.Domains)
	d.sql.QueryRow("SELECT count(*) FROM dns").Scan(&sm.DNS)

	sm.TopProc = d.topQuery("SELECT coalesce(nullif(image,''),'System') k, count(*) n FROM conn GROUP BY k ORDER BY n DESC LIMIT 8")
	sm.TopPort = d.topQuery("SELECT printf('%d %s', dst_port, coalesce(port_name,'')) k, count(*) n FROM conn WHERE dst_port>0 GROUP BY dst_port ORDER BY n DESC LIMIT 10")
	sm.TopGeo = d.topQuery("SELECT geo k, count(*) n FROM conn WHERE geo!='' GROUP BY geo ORDER BY n DESC LIMIT 10")
	sm.TopDst = d.topQuery("SELECT dst_ip k, count(*) n FROM conn WHERE public=1 GROUP BY dst_ip ORDER BY n DESC LIMIT 10")

	for _, r := range []string{"R1", "R2", "R3", "R4", "R5", "R6"} {
		var n int
		d.sql.QueryRow("SELECT count(*) FROM conn WHERE risk LIKE ?", "%"+r+"%").Scan(&n)
		if n > 0 {
			sm.Rules = append(sm.Rules, Count{Key: r, N: n})
		}
	}
	sort.Slice(sm.Rules, func(i, j int) bool { return sm.Rules[i].N > sm.Rules[j].N })

	span := sm.To - sm.From
	step := int64(60 * 1000)
	switch {
	case span > 30*24*3600*1000:
		step = 24 * 3600 * 1000
	case span > 72*3600*1000:
		step = 3600 * 1000
	}
	if span/step > 700 {
		step = span / 700
		if step < 60000 {
			step = 60000
		}
	}
	sm.Step = step
	if sm.Conns > 0 {
		rows, err := d.sql.Query("SELECT ts - ts % ? AS b, count(*) FROM conn GROUP BY b ORDER BY b", step)
		if err == nil {
			for rows.Next() {
				var b Bucket
				rows.Scan(&b.T, &b.N)
				sm.Timeline = append(sm.Timeline, b)
			}
			rows.Close()
		}
	}

	rows, err := d.sql.Query("SELECT name FROM file ORDER BY name")
	if err == nil {
		for rows.Next() {
			var n string
			rows.Scan(&n)
			sm.Files = append(sm.Files, n)
		}
		rows.Close()
	}
	return sm, nil
}

func (d *DB) topQuery(q string) []Count {
	rows, err := d.sql.Query(q)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if rows.Scan(&c.Key, &c.N) == nil {
			out = append(out, c)
		}
	}
	return out
}

// Values 返回某字段出现最多的取值，用于界面点选筛选。
func (d *DB) Values(name string, limit int) ([]Count, error) {
	col, _, err := d.resolve(name)
	if err != nil {
		return nil, err
	}
	q := "SELECT " + col + " k, count(*) n FROM conn WHERE " + col + " IS NOT NULL AND " + col + " != '' GROUP BY k ORDER BY n DESC LIMIT ?"
	rows, err := d.sql.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if rows.Scan(&c.Key, &c.N) == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (d *DB) DNSValues(name string, limit int) ([]Count, error) {
	col, _, err := dnsField(name)
	if err != nil {
		return nil, err
	}
	q := "SELECT " + col + " k, count(*) n FROM dns WHERE " + col + " IS NOT NULL AND " + col + " != '' GROUP BY k ORDER BY n DESC LIMIT ?"
	rows, err := d.sql.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if rows.Scan(&c.Key, &c.N) == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (d *DB) ProcessValues(name string, limit int) ([]Count, error) {
	col, _, err := processField(name)
	if err != nil {
		return nil, err
	}
	q := "SELECT " + col + " k, count(*) n FROM process_event WHERE event_id=1 AND " +
		col + " IS NOT NULL AND " + col + " != '' GROUP BY k ORDER BY n DESC LIMIT ?"
	rows, err := d.sql.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if rows.Scan(&c.Key, &c.N) == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (d *DB) QueryDNS(q string, limit int) ([]*DNSQ, int, error) {
	total, err := d.CountDNSFiltered(q)
	if err != nil {
		return nil, 0, err
	}
	rows, err := d.PageDNS(q, limit, 0, "ts", true)
	if err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

func dnsOrderClause(sortField string, desc bool) (string, error) {
	columns := map[string]int{
		"ts": 1, "host": 2, "pid": 3, "guid": 4, "image": 5, "user": 6,
		"query": 7, "results": 8, "geo": 9, "country": 10, "risk": 11,
		"status": 12, "rule_name": 13,
	}
	if sortField == "" {
		sortField = "ts"
	}
	col, ok := columns[sortField]
	if !ok {
		return "", fmt.Errorf("DNS 不支持排序字段: %s", sortField)
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return fmt.Sprintf("%d %s, 1 DESC, id DESC", col, dir), nil
}

func (d *DB) PageDNS(q string, limit, offset int, sortField string, desc bool) ([]*DNSQ, error) {
	return d.PageDNSAsOf(q, limit, offset, sortField, desc, 0)
}

func (d *DB) PageDNSAsOf(q string, limit, offset int, sortField string, desc bool, asOf int64) ([]*DNSQ, error) {
	where, args := "1=1", []interface{}{}
	if q != "" {
		var err error
		where, args, err = d.compileDNS(q)
		if err != nil {
			return nil, err
		}
	}
	if asOf > 0 {
		where = "(" + where + ") AND ts<=?"
		args = append(args, asOf)
	}
	order, err := dnsOrderClause(sortField, desc)
	if err != nil {
		return nil, err
	}
	query := "SELECT ts,host,pid,guid,image,user,query,results,geo,country,risk,status," +
		"coalesce(json_extract(raw,'$.RuleName'),''),raw FROM dns WHERE " +
		where + " ORDER BY " + order
	queryArgs := append([]interface{}{}, args...)
	if limit > 0 {
		query += " LIMIT ? OFFSET ?"
		queryArgs = append(queryArgs, limit, offset)
	}
	rows, err := d.sql.Query(query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DNSQ{}
	for rows.Next() {
		x := &DNSQ{}
		var risk string
		var raw []byte
		if err := rows.Scan(&x.TS, &x.Host, &x.PID, &x.Guid, &x.Image, &x.User,
			&x.Query, &x.Results, &x.Geo, &x.Country, &risk, &x.Status, &x.Rule, &raw); err != nil {
			return nil, err
		}
		x.Risk = strings.Fields(risk)
		if len(raw) > 0 {
			var m map[string]string
			if json.Unmarshal(raw, &m) == nil {
				x.Raw = m
				if x.Rule == "" {
					x.Rule = m["RuleName"]
				}
			}
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

type procRow struct {
	Guid    string `json:"guid"`
	Host    string `json:"host"`
	Image   string `json:"image"`
	PID     string `json:"pid"`
	User    string `json:"user"`
	CmdLine string `json:"cmdLine"`
	Parent  string `json:"parent"`
	Hashes  string `json:"hashes"`
	Rule    string `json:"ruleName"`
	Source  string `json:"source"`
	Start   int64  `json:"start"`
	End     int64  `json:"end"`
	N       int    `json:"n"`
	Pub     int    `json:"pub"`
	IPs     int    `json:"ips"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
	Risky   int    `json:"risky"`
}

// QueryProcs 按进程聚合当前筛选结果，供原生「进程」页使用。
func (d *DB) QueryProcs(expr string) ([]procRow, error) {
	return d.queryProcs(expr, 800, 0, "start", true)
}

// ExportProcs 返回全部进程聚合结果，供导出 CSV 使用。
func (d *DB) ExportProcs(expr string) ([]procRow, error) {
	return d.queryProcs(expr, 0, 0, "start", true)
}

func (d *DB) PageProcs(expr string, limit, offset int, sortField string, desc bool) ([]procRow, error) {
	return d.PageProcsAsOf(expr, limit, offset, sortField, desc, 0)
}

func (d *DB) PageProcsAsOf(expr string, limit, offset int, sortField string, desc bool, asOf int64) ([]procRow, error) {
	where, args, err := d.compileProcess(expr)
	if err != nil {
		return nil, err
	}
	if asOf > 0 {
		where = "(" + where + ") AND ts<=?"
		args = append(args, asOf)
	}
	order, err := processOrderClause(sortField, desc)
	if err != nil {
		return nil, err
	}
	q := `SELECT guid,coalesce(host,''),
		coalesce(nullif(image,''),'System'),coalesce(pid,''),coalesce(user,''),
		coalesce(cmdline,''),coalesce(parent_image,''),coalesce(hashes,''),
		coalesce(rule_name,''),coalesce(ts,0),coalesce(end_ts,0),
		coalesce(source,''),coalesce(n,0),coalesce(pub,0),coalesce(ips,0),
		coalesce(first_ts,0),coalesce(last_ts,0),coalesce(risky,0)
		FROM process_list_view WHERE ` + where + ` ORDER BY ` + order
	if limit > 0 {
		q += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	rows, err := d.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []procRow{}
	for rows.Next() {
		var p procRow
		if err := rows.Scan(&p.Guid, &p.Host, &p.Image, &p.PID, &p.User, &p.CmdLine,
			&p.Parent, &p.Hashes, &p.Rule, &p.Start, &p.End, &p.Source,
			&p.N, &p.Pub, &p.IPs, &p.First, &p.Last, &p.Risky); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func processOrderClause(sortField string, desc bool) (string, error) {
	columns := map[string]string{
		"guid": "guid", "host": "host", "image": "image", "pid": "pid",
		"user": "user", "cmdline": "cmdline", "parent": "parent_image",
		"hashes": "hashes", "rule_name": "rule_name", "start": "ts",
		"end": "end_ts", "source": "source", "n": "n", "pub": "pub",
		"ips": "ips", "first": "first_ts", "last": "last_ts", "risky": "risky",
	}
	if sortField == "" {
		sortField = "start"
	}
	col, ok := columns[sortField]
	if !ok {
		return "", fmt.Errorf("进程不支持排序字段: %s", sortField)
	}
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	return fmt.Sprintf("%s %s, ts DESC, guid ASC", col, dir), nil
}

func (d *DB) queryProcs(expr string, limit, offset int, sortField string, desc bool) ([]procRow, error) {
	return d.PageProcsAsOf(expr, limit, offset, sortField, desc, 0)
}

func (d *DB) queryProcsAsOf(expr string, limit, offset int, sortField string, desc bool, asOf int64) ([]procRow, error) {
	connWhere, connArgs, connErr := d.compile(expr)
	procWhere, procArgs, procErr := d.compileProcess(expr)
	if strings.TrimSpace(expr) != "" && connErr != nil && procErr != nil {
		return nil, procErr
	}
	if connErr != nil {
		connWhere, connArgs = "1=1", nil
	}
	if procErr != nil {
		procWhere, procArgs = "1=1", nil
	}
	procFilter := "(" + procWhere + ")"
	connFilter := "(" + connWhere + ")"
	endFilter := ""
	if asOf > 0 {
		procFilter += " AND ts<=?"
		connFilter += " AND ts<=?"
		endFilter = " AND ts<=?"
		procArgs = append(procArgs, asOf)
		connArgs = append(connArgs, asOf)
	}
	eventFilter := ""
	unionConn := connErr == nil
	if procErr != nil {
		eventFilter = " WHERE guid IN (SELECT guid FROM conn_stats)"
	}
	order, err := processOrderClause(sortField, desc)
	if err != nil {
		return nil, err
	}
	q := `WITH ev_start AS (
		SELECT guid,ts,host,pid,image,cmdline,user,integrity,hashes,
			parent_guid,parent_pid,parent_image,parent_cmdline,rule_name,source
		FROM (
			SELECT *, row_number() OVER (PARTITION BY guid ORDER BY ts ASC) rn
			FROM process_event WHERE event_id=1 AND ` + procFilter + `
		) WHERE rn=1
	),
	ev_end AS (
		SELECT guid,max(ts) end_ts FROM process_event WHERE event_id=5` + endFilter + ` GROUP BY guid
	),
	conn_base AS (
		SELECT guid,ts,host,image,pid,user,cmdline,parent,hashes,source,public,dst_ip,risk,
			row_number() OVER (PARTITION BY guid ORDER BY ts DESC) rn
		FROM conn WHERE ` + connFilter + `
	),
	conn_stats AS (
		SELECT guid,
			coalesce(max(CASE WHEN rn=1 THEN host END),'') host,
			coalesce(max(CASE WHEN rn=1 THEN image END),'') image,
			coalesce(max(CASE WHEN rn=1 THEN pid END),'') pid,
			coalesce(max(CASE WHEN rn=1 THEN user END),'') user,
			coalesce(max(CASE WHEN rn=1 THEN cmdline END),'') cmdline,
			coalesce(max(CASE WHEN rn=1 THEN parent END),'') parent,
			coalesce(max(CASE WHEN rn=1 THEN hashes END),'') hashes,
			coalesce(group_concat(DISTINCT NULLIF(source,'')),'') source,
			count(*) n, coalesce(sum(public),0) pub, count(DISTINCT dst_ip) ips,
			min(ts) first, max(ts) last, sum(CASE WHEN risk!='' THEN 1 ELSE 0 END) risky
		FROM conn_base GROUP BY guid
	),
	guids AS (
		SELECT guid FROM ev_start` + eventFilter + `
		` + func() string {
		if unionConn {
			return "UNION SELECT guid FROM conn_stats"
		}
		return ""
	}() + `
	)
	SELECT g.guid,
		coalesce(s.host,c.host,''),
		coalesce(nullif(s.image,''),nullif(c.image,''),'System'),
		coalesce(s.pid,c.pid,''),
		coalesce(s.user,c.user,''),
		coalesce(s.cmdline,c.cmdline,''),
		coalesce(s.parent_image,c.parent,''),
		coalesce(s.hashes,c.hashes,''),
		coalesce(s.rule_name,''),
		coalesce(s.ts,0), coalesce(e.end_ts,0),
		CASE
			WHEN coalesce(s.source,'')='' THEN coalesce(c.source,'')
			WHEN coalesce(c.source,'')='' OR c.source=s.source THEN s.source
			ELSE s.source || ',' || c.source
		END,
		coalesce(c.n,0), coalesce(c.pub,0), coalesce(c.ips,0),
		coalesce(c.first,0), coalesce(c.last,0), coalesce(c.risky,0)
	FROM guids g
	LEFT JOIN ev_start s ON s.guid=g.guid
	LEFT JOIN ev_end e ON e.guid=g.guid
	LEFT JOIN conn_stats c ON c.guid=g.guid
	ORDER BY ` + order
	args := append([]interface{}{}, procArgs...)
	if asOf > 0 {
		args = append(args, asOf)
	}
	args = append(args, connArgs...)
	if limit > 0 {
		q += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	rows, err := d.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []procRow{}
	for rows.Next() {
		var p procRow
		if err := rows.Scan(&p.Guid, &p.Host, &p.Image, &p.PID, &p.User, &p.CmdLine,
			&p.Parent, &p.Hashes, &p.Rule, &p.Start, &p.End, &p.Source,
			&p.N, &p.Pub, &p.IPs, &p.First, &p.Last, &p.Risky); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ExportDNSRows 返回当前筛选结果的 DNS 记录，供导出 CSV 使用。
func (d *DB) ExportDNSRows(expr string) (*sql.Rows, error) {
	where, args, err := d.compileDNS(expr)
	if err != nil {
		return nil, err
	}
	return d.sql.Query(`SELECT ts,host,pid,guid,image,user,query,results,geo,country,risk,status,
		coalesce(json_extract(raw,'$.RuleName'),'') FROM dns WHERE `+where+` ORDER BY ts DESC`, args...)
}

// RiskCounts 返回 R1–R6 在当前筛选结果里的命中数量。
func (d *DB) RiskCounts(expr string) ([]Count, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, err
	}
	out := make([]Count, 0, 6)
	for _, r := range []string{"R1", "R2", "R3", "R4", "R5", "R6"} {
		qArgs := append(append([]interface{}{}, args...), "%"+r+"%")
		var n int
		if err := d.sql.QueryRow("SELECT count(*) FROM conn WHERE ("+where+") AND risk LIKE ?", qArgs...).Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, Count{Key: r, N: n})
	}
	return out, nil
}

type IRStatRow struct {
	Key     string `json:"key"`
	N       int    `json:"n"`
	Public  int    `json:"public,omitempty"`
	Risky   int    `json:"risky,omitempty"`
	Targets int    `json:"targets,omitempty"`
	Sub     string `json:"sub,omitempty"`
}

type IRStats struct {
	Conns     int         `json:"conns"`
	Public    int         `json:"public"`
	Outbound  int         `json:"outbound"`
	Processes int         `json:"processes"`
	DstIPs    int         `json:"dstIps"`
	Domains   int         `json:"domains"`
	TopProc   []IRStatRow `json:"topProc"`
	TopIP     []IRStatRow `json:"topIp"`
	TopDomain []IRStatRow `json:"topDomain"`
	Risks     []Count     `json:"risks"`
}

func (d *DB) IRStats(expr string) (*IRStats, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, err
	}
	st := &IRStats{}
	if err := d.sql.QueryRow(`SELECT count(*), coalesce(sum(public),0), coalesce(sum(outbound),0),
		count(DISTINCT NULLIF(image,'')), count(DISTINCT NULLIF(dst_ip,'')),
		count(DISTINCT NULLIF(dst_host,'')) FROM conn WHERE `+where, args...).
		Scan(&st.Conns, &st.Public, &st.Outbound, &st.Processes, &st.DstIPs, &st.Domains); err != nil {
		return nil, err
	}

	rows, err := d.sql.Query(`SELECT coalesce(nullif(image,''),'System'), count(*),
		coalesce(sum(public),0), sum(CASE WHEN risk!='' THEN 1 ELSE 0 END)
		FROM conn WHERE `+where+` GROUP BY image ORDER BY count(*) DESC LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r IRStatRow
		if err := rows.Scan(&r.Key, &r.N, &r.Public, &r.Risky); err != nil {
			rows.Close()
			return nil, err
		}
		st.TopProc = append(st.TopProc, r)
	}
	rows.Close()

	rows, err = d.sql.Query(`SELECT dst_ip,count(*),coalesce(geo,''),
		sum(CASE WHEN risk!='' THEN 1 ELSE 0 END),count(DISTINCT NULLIF(image,''))
		FROM conn WHERE (`+where+`) AND dst_ip!=''
		GROUP BY dst_ip ORDER BY count(*) DESC LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r IRStatRow
		if err := rows.Scan(&r.Key, &r.N, &r.Sub, &r.Risky, &r.Targets); err != nil {
			rows.Close()
			return nil, err
		}
		st.TopIP = append(st.TopIP, r)
	}
	rows.Close()

	rows, err = d.sql.Query(`SELECT dst_host,count(*),count(DISTINCT NULLIF(dst_ip,'')),
		sum(CASE WHEN risk!='' THEN 1 ELSE 0 END)
		FROM conn WHERE (`+where+`) AND dst_host!=''
		GROUP BY dst_host ORDER BY count(*) DESC LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r IRStatRow
		if err := rows.Scan(&r.Key, &r.N, &r.Targets, &r.Risky); err != nil {
			rows.Close()
			return nil, err
		}
		st.TopDomain = append(st.TopDomain, r)
	}
	rows.Close()

	st.Risks, err = d.RiskCounts(expr)
	if err != nil {
		return nil, err
	}
	return st, nil
}

type ProcessStats struct {
	Total              int         `json:"total"`
	WithNetwork        int         `json:"withNetwork"`
	WithoutNetwork     int         `json:"withoutNetwork"`
	Ended              int         `json:"ended"`
	Connections        int         `json:"connections"`
	PublicConnections  int         `json:"publicConnections"`
	RiskyConnections   int         `json:"riskyConnections"`
	Users              int         `json:"users"`
	TopProcess         []IRStatRow `json:"topProcess"`
	TopParent          []IRStatRow `json:"topParent"`
	TopUser            []IRStatRow `json:"topUser"`
	TopProcessWithRisk []IRStatRow `json:"topProcessWithRisk"`
}

func (d *DB) ProcessStats(expr string) (*ProcessStats, error) {
	rows, err := d.queryProcs(expr, 0, 0, "start", true)
	if err != nil {
		return nil, err
	}
	st := &ProcessStats{}
	processes := map[string]int{}
	parents := map[string]int{}
	users := map[string]int{}
	risky := map[string]int{}
	for _, p := range rows {
		st.Total++
		if p.N > 0 {
			st.WithNetwork++
		} else {
			st.WithoutNetwork++
		}
		if p.End > 0 {
			st.Ended++
		}
		st.Connections += p.N
		st.PublicConnections += p.Pub
		st.RiskyConnections += p.Risky
		processName := statValue(p.Image, "System")
		processes[processName]++
		parents[statValue(p.Parent, "(未知父进程)")]++
		users[statValue(p.User, "(未知用户)")]++
		if p.Risky > 0 {
			risky[processName] += p.Risky
		}
	}
	st.Users = len(users)
	st.TopProcess = topStatRows(processes, 20)
	st.TopParent = topStatRows(parents, 20)
	st.TopUser = topStatRows(users, 20)
	st.TopProcessWithRisk = topStatRows(risky, 20)
	return st, nil
}

type DNSStats struct {
	Total      int         `json:"total"`
	Domains    int         `json:"domains"`
	Results    int         `json:"results"`
	Processes  int         `json:"processes"`
	Failed     int         `json:"failed"`
	Foreign    int         `json:"foreign"`
	Sources    int         `json:"sources"`
	TopDomain  []IRStatRow `json:"topDomain"`
	TopProcess []IRStatRow `json:"topProcess"`
	TopResult  []IRStatRow `json:"topResult"`
	TopStatus  []IRStatRow `json:"topStatus"`
	TopRule    []IRStatRow `json:"topRule"`
	Risks      []Count     `json:"risks"`
}

func (d *DB) DNSStats(expr string) (*DNSStats, error) {
	where, args, err := d.compileDNS(expr)
	if err != nil {
		return nil, err
	}
	st := &DNSStats{}
	if err := d.sql.QueryRow(`SELECT count(*),
		count(DISTINCT NULLIF(query,'')),
		count(DISTINCT NULLIF(results,'')),
		count(DISTINCT NULLIF(image,'')),
		coalesce(sum(CASE WHEN status!='' AND status!='0' THEN 1 ELSE 0 END),0),
		coalesce(sum(CASE WHEN risk LIKE '%D1%' THEN 1 ELSE 0 END),0),
		count(DISTINCT NULLIF(source,''))
		FROM dns WHERE `+where, args...).
		Scan(&st.Total, &st.Domains, &st.Results, &st.Processes, &st.Failed, &st.Foreign, &st.Sources); err != nil {
		return nil, err
	}

	st.TopDomain, err = d.queryStatRows(`SELECT query,count(*),
		count(DISTINCT NULLIF(results,'')),
		coalesce(sum(CASE WHEN status!='' AND status!='0' THEN 1 ELSE 0 END),0)
		FROM dns WHERE (`+where+`) AND query!=''
		GROUP BY query ORDER BY count(*) DESC LIMIT 20`, args)
	if err != nil {
		return nil, err
	}
	st.TopProcess, err = d.queryStatRows(`SELECT coalesce(nullif(image,''),'System'),count(*),
		count(DISTINCT NULLIF(query,'')),
		coalesce(sum(CASE WHEN status!='' AND status!='0' THEN 1 ELSE 0 END),0)
		FROM dns WHERE `+where+`
		GROUP BY image ORDER BY count(*) DESC LIMIT 20`, args)
	if err != nil {
		return nil, err
	}
	st.TopStatus, err = d.queryStatRows(`SELECT coalesce(nullif(status,''),'(空)'),count(*),0,0
		FROM dns WHERE `+where+`
		GROUP BY status ORDER BY count(*) DESC LIMIT 20`, args)
	if err != nil {
		return nil, err
	}
	st.TopRule, err = d.queryStatRows(`SELECT coalesce(nullif(json_extract(raw,'$.RuleName'),''),'(无规则)'),count(*),0,0
		FROM dns WHERE `+where+`
		GROUP BY 1 ORDER BY count(*) DESC LIMIT 20`, args)
	if err != nil {
		return nil, err
	}

	resultCounts := map[string]*IRStatRow{}
	rows, err := d.sql.Query(`SELECT results FROM dns WHERE (`+where+`) AND results!=''`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var results string
		if err := rows.Scan(&results); err != nil {
			rows.Close()
			return nil, err
		}
		for _, ip := range dnsIPs(results) {
			row := resultCounts[ip]
			if row == nil {
				geo := ""
				if d.geo != nil && isPublicIP(ip) {
					geo, _ = d.geo.LookupInfo(ip)
				}
				row = &IRStatRow{Key: ip, Sub: geo}
				resultCounts[ip] = row
			}
			row.N++
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	st.TopResult = make([]IRStatRow, 0, len(resultCounts))
	for _, row := range resultCounts {
		st.TopResult = append(st.TopResult, *row)
	}
	sort.Slice(st.TopResult, func(i, j int) bool {
		if st.TopResult[i].N == st.TopResult[j].N {
			return st.TopResult[i].Key < st.TopResult[j].Key
		}
		return st.TopResult[i].N > st.TopResult[j].N
	})
	if len(st.TopResult) > 20 {
		st.TopResult = st.TopResult[:20]
	}
	st.Results = len(resultCounts)
	for _, code := range []string{dnsRiskForeign, dnsRiskFailed, dnsRiskEmpty} {
		qArgs := append(append([]interface{}{}, args...), "%"+code+"%")
		var n int
		if err := d.sql.QueryRow("SELECT count(*) FROM dns WHERE ("+where+") AND risk LIKE ?", qArgs...).Scan(&n); err != nil {
			return nil, err
		}
		st.Risks = append(st.Risks, Count{Key: code, N: n})
	}
	return st, nil
}

func (d *DB) queryStatRows(query string, args []interface{}) ([]IRStatRow, error) {
	rows, err := d.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IRStatRow{}
	for rows.Next() {
		var r IRStatRow
		if err := rows.Scan(&r.Key, &r.N, &r.Targets, &r.Risky); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func statValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func topStatRows(counts map[string]int, limit int) []IRStatRow {
	rows := make([]IRStatRow, 0, len(counts))
	for key, n := range counts {
		if strings.TrimSpace(key) == "" || n <= 0 {
			continue
		}
		rows = append(rows, IRStatRow{Key: key, N: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].N == rows[j].N {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].N > rows[j].N
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// Fields 返回可筛选字段清单（提升字段 + 事件原始字段）。
func (d *DB) Fields() ([]FieldMeta, error) {
	out := append([]FieldMeta{}, promoted...)
	rows, err := d.sql.Query("SELECT name FROM rawfield ORDER BY name")
	if err != nil {
		return out, nil
	}
	defer rows.Close()
	var raws []FieldMeta
	for rows.Next() {
		var n string
		rows.Scan(&n)
		if _, ok := promotedIdx[n]; ok {
			continue
		}
		key := strings.ToLower(n)
		if rawFieldIgnored[key] {
			continue
		}
		if _, ok := rawFieldAliases[key]; ok {
			continue
		}
		label, ok := rawFieldLabels[key]
		if !ok {
			continue
		}
		raws = append(raws, FieldMeta{Name: n, Label: label, Type: "text", Raw: true})
	}
	sort.Slice(raws, func(i, j int) bool { return raws[i].Name < raws[j].Name })
	return append(out, raws...), nil
}

// Meta 汇总界面需要的元信息。
func (d *DB) Meta() (map[string]interface{}, error) {
	fields, _ := d.Fields()
	var events, conns, dnss int
	d.sql.QueryRow("SELECT coalesce(sum(events),0) FROM file").Scan(&events)
	d.sql.QueryRow("SELECT count(*) FROM conn").Scan(&conns)
	d.sql.QueryRow("SELECT count(*) FROM dns").Scan(&dnss)
	processes, _ := d.CountProcesses()
	var files []string
	sources := []map[string]interface{}{}
	if rows, err := d.sql.Query("SELECT name, events, coalesce(path,''), coalesce(bytes,0), imported_at FROM file ORDER BY name"); err == nil {
		for rows.Next() {
			var n, path string
			var ev, size, at int64
			if rows.Scan(&n, &ev, &path, &size, &at) == nil {
				files = append(files, n)
				sources = append(sources, map[string]interface{}{
					"name": n, "kind": "file", "path": path, "bytes": size,
					"events": ev, "at": at,
				})
			}
		}
		rows.Close()
	}
	return map[string]interface{}{
		"fields": fields, "events": events, "conns": conns, "processes": processes, "dns": dnss, "files": files,
		"sources": sources, "version": version, "rules": ruleText,
	}, nil
}

// Close 关闭数据库（WAL 会在关闭时合并）。
func (d *DB) Close() error { return d.sql.Close() }
