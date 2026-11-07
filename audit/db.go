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
}

var promotedIdx = map[string]FieldMeta{}

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
	sqldb.SetMaxOpenConns(1)
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
			integrity TEXT, rule_name TEXT, risk TEXT, raw TEXT,
			UNIQUE(guid, ts, dst_ip, dst_port, proto)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conn_ts ON conn(ts)`,
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
			query TEXT, results TEXT, status TEXT, raw TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_query ON dns(query)`,
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
	// 全文索引：trigram 支持子串匹配（ASCII 不区分大小写，中文需 >=3 个字）。
	if _, err := d.sql.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS conn_fts USING fts5(image, cmdline, dst_host, geo, content='', tokenize='trigram')`); err != nil {
		return err
	}
	return nil
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
	rawKeys := map[string]int{}

	for i := range evs {
		e := &evs[i]
		switch e.EID {
		case "1":
			g := e.get("ProcessGuid")
			if g == "" {
				continue
			}
			d.procCache[g] = &procInfo{Image: e.get("Image"), CmdLine: e.get("CommandLine"), Parent: e.get("ParentImage"), Hashes: e.get("Hashes"), User: e.get("User"), Integ: e.get("IntegrityLevel")}
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

	n, err := d.writeBatch(src, conns, dnss, rawKeys, len(evs), strings.HasPrefix(src, liveSource))
	if err != nil {
		return 0, 0, err
	}
	return n, len(dnss), nil
}

func (d *DB) writeBatch(file string, conns []*Conn, dnss []*DNSQ, rawKeys map[string]int, events int, merge bool) (int, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	insConn, err := tx.Prepare(`INSERT OR IGNORE INTO conn(ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk,raw)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insConn.Close()
	insFTS, err := tx.Prepare(`INSERT INTO conn_fts(rowid,image,cmdline,dst_host,geo) VALUES(?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer insFTS.Close()

	n := 0
	for _, c := range conns {
		raw, _ := json.Marshal(c.Raw)
		res, err := insConn.Exec(c.TS, c.Host, c.PID, c.Guid, c.Image, c.User, c.Proto, c.SrcIP, c.SrcPort, c.DstIP, atoi(c.DstPort), c.DstHost, c.PortNm, b2i(c.Out), b2i(c.V6), c.Geo, b2i(c.Public), c.CmdLine, c.Parent, c.Hashes, c.Integ, c.Rule, strings.Join(c.Risk, " "), string(raw))
		if err != nil {
			return n, err
		}
		if aff, _ := res.RowsAffected(); aff == 0 {
			continue
		}
		id, _ := res.LastInsertId()
		n++
		if _, err := insFTS.Exec(id, c.Image, c.CmdLine, c.DstHost, c.Geo); err != nil {
			return n, err
		}
	}

	if len(dnss) > 0 {
		insDNS, err := tx.Prepare(`INSERT INTO dns(ts,host,pid,guid,image,user,query,results,status,raw) VALUES(?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return n, err
		}
		defer insDNS.Close()
		for _, q := range dnss {
			raw, _ := json.Marshal(q.Raw)
			if _, err := insDNS.Exec(q.TS, q.Host, q.PID, q.Guid, q.Image, q.User, q.Query, q.Results, q.Status, string(raw)); err != nil {
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
// 语法：空格=AND，| 或 OR=OR，- 或 NOT=取反，括号可分组。
// 优先级：NOT > AND > OR。
func (d *DB) compile(expr string) (string, []interface{}, error) {
	toks := tokenize(expr)
	if len(toks) == 0 {
		return "1=1", nil, nil
	}
	p := &parser{toks: toks, d: d}
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
	toks []string
	pos  int
	d    *DB
	args []interface{}
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
	var parts []string
	for p.pos < len(p.toks) {
		t := p.peek()
		if t == ")" || isOr(t) {
			break
		}
		if isAnd(t) {
			p.pos++
			continue
		}
		c, err := p.parseUnary()
		if err != nil {
			return "", err
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("语法错误：这里缺条件")
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
	c, a, err := p.d.cond(t)
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

func findOp(tok string) (string, int) {
	for _, op := range []string{"!=", ">=", "<=", ":", "=", "~", ">", "<"} {
		if i := strings.Index(tok, op); i > 0 {
			return op, i
		}
	}
	return "", -1
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

// textCond 全文检索：>=3 个字符走 FTS5 trigram，过短退化为 LIKE。
func (d *DB) textCond(q string) (string, []interface{}, error) {
	if len([]rune(q)) >= 3 {
		match := `"` + strings.ReplaceAll(q, `"`, "") + `"`
		return "conn.id IN (SELECT rowid FROM conn_fts WHERE conn_fts MATCH ?)", []interface{}{match}, nil
	}
	like := "%" + q + "%"
	return "(image LIKE ? OR cmdline LIKE ? OR dst_host LIKE ? OR geo LIKE ? OR dst_ip LIKE ?)",
		[]interface{}{like, like, like, like, like}, nil
}

// Query 执行查询，返回分页结果与总数。
func (d *DB) Query(expr string, limit, offset int, sortField string, desc bool) ([]*Conn, int, error) {
	where, args, err := d.compile(expr)
	if err != nil {
		return nil, 0, err
	}
	var total int
	if err := d.sql.QueryRow("SELECT count(*) FROM conn WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := "ts DESC"
	if sortField != "" {
		col, _, err := d.resolve(sortField)
		if err != nil {
			return nil, 0, err
		}
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		order = col + " " + dir + ", ts DESC"
	}
	q := "SELECT " + connCols + " FROM conn WHERE " +
		where + " ORDER BY " + order + " LIMIT ? OFFSET ?"
	rows, err := d.sql.Query(q, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Conn, 0, limit)
	for rows.Next() {
		c, err := scanConn(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

type scanner interface{ Scan(...interface{}) error }

func scanConn(rows scanner) (*Conn, error) {
	return scanConnWithRaw(rows, true)
}

// connCols 是 scanConn 读取的完整列；connColsNoRaw 用于导出，省掉 raw JSON。
const connCols = "id,ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk,raw"

const connColsNoRaw = "id,ts,host,pid,guid,image,user,proto,src_ip,src_port,dst_ip,dst_port,dst_host,port_name,outbound,ipv6,geo,public,cmdline,parent,hashes,integrity,rule_name,risk"

func scanConnWithRaw(rows scanner, withRaw bool) (*Conn, error) {
	c := &Conn{}
	var out, v6, pub int
	var risk string
	if withRaw {
		var raw []byte
		if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.PID, &c.Guid, &c.Image, &c.User, &c.Proto, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort, &c.DstHost, &c.PortNm, &out, &v6, &c.Geo, &pub, &c.CmdLine, &c.Parent, &c.Hashes, &c.Integ, &c.Rule, &risk, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			var m map[string]string
			if json.Unmarshal(raw, &m) == nil {
				c.Raw = m
			}
		}
	} else if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.PID, &c.Guid, &c.Image, &c.User, &c.Proto, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort, &c.DstHost, &c.PortNm, &out, &v6, &c.Geo, &pub, &c.CmdLine, &c.Parent, &c.Hashes, &c.Integ, &c.Rule, &risk); err != nil {
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

	for _, r := range []string{"R1", "R2", "R3", "R4", "R5"} {
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

func (d *DB) QueryDNS(q string, limit int) ([]*DNSQ, int, error) {
	where, args := "1=1", []interface{}{}
	if q != "" {
		where = "(query LIKE ? OR image LIKE ? OR results LIKE ?)"
		l := "%" + q + "%"
		args = []interface{}{l, l, l}
	}
	var total int
	if err := d.sql.QueryRow("SELECT count(*) FROM dns WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.sql.Query("SELECT ts,host,pid,guid,image,user,query,results,status,raw FROM dns WHERE "+where+" ORDER BY ts DESC LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*DNSQ{}
	for rows.Next() {
		x := &DNSQ{}
		var raw []byte
		if err := rows.Scan(&x.TS, &x.Host, &x.PID, &x.Guid, &x.Image, &x.User, &x.Query, &x.Results, &x.Status, &raw); err != nil {
			return nil, 0, err
		}
		if len(raw) > 0 {
			var m map[string]string
			if json.Unmarshal(raw, &m) == nil {
				x.Raw = m
			}
		}
		out = append(out, x)
	}
	return out, total, rows.Err()
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
		raws = append(raws, FieldMeta{Name: n, Label: n, Type: "text", Raw: true})
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
		"fields": fields, "events": events, "conns": conns, "dns": dnss, "files": files,
		"sources": sources, "version": version, "rules": ruleText,
	}, nil
}

// Close 关闭数据库（WAL 会在关闭时合并）。
func (d *DB) Close() error { return d.sql.Close() }
