package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui
var uiFS embed.FS

var ruleText = map[string]string{
	"R1": "非常规端口外联",
	"R2": "非浏览器进程访问 Web 端口",
	"R3": "临时/下载目录进程外联",
	"R4": "直接连接公网 IP（无域名）",
	"R5": "短时间大量外联目标",
	"R6": "连接境外 IP（非中国大陆）",
}

type server struct {
	db       *DB
	token    string
	loc      *time.Location
	dataDir  string
	channel  string
	interval time.Duration

	liveMu sync.Mutex
	live   *LiveStats

	quit chan struct{}
}

// enableLive 启动实时采集（幂等）。返回是否本次真正启动。
func (s *server) enableLive() bool {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live != nil {
		return false
	}
	if err := liveSupported(); err != nil {
		return false
	}
	cfg := liveConfig{Channel: s.channel, Interval: s.interval, DataDir: s.dataDir}
	if cfg.Channel == "" {
		cfg.Channel = defaultChannel
	}
	st := &LiveStats{}
	s.live = st
	go startLive(s.db, st, cfg, func(f string, a ...interface{}) { appPrintf(f, a...) })
	return true
}

// disableLive 停止实时采集（卸载 Sysmon 时调用）。
func (s *server) disableLive() {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live != nil {
		s.live.stop("已停止（Sysmon 已卸载）")
		s.live = nil
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/meta", s.handleMeta)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/conns", s.handleConns)
	mux.HandleFunc("/api/procs", s.handleProcs)
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/values", s.handleValues)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/import", s.handleImport)
	mux.HandleFunc("/api/import/upload", s.handleUpload)
	mux.HandleFunc("/api/source/delete", s.handleSourceDelete)
	mux.HandleFunc("/api/live", s.handleLive)
	mux.HandleFunc("/api/live/toggle", s.handleLiveToggle)
	mux.HandleFunc("/api/exit", s.handleExit)
	mux.HandleFunc("/api/sysmon", s.handleSysmon)
	mux.HandleFunc("/api/sysmon/install", s.handleSysmonInstall)
	mux.HandleFunc("/api/sysmon/args", s.handleSysmonArgs)
	mux.HandleFunc("/api/sysmon/uninstall", s.handleSysmonUninstall)
	mux.HandleFunc("/api/sysmon/logsize", s.handleSysmonLogSize)
	return s.auth(mux)
}

func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("ta_token"); err == nil && c.Value == s.token {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Query().Get("t") == s.token {
			http.SetCookie(w, &http.Cookie{Name: "ta_token", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			if r.URL.Path == "/" {
				// 去掉 token，但保留 expr 等参数，便于分享检索链接。
				q := r.URL.Query()
				q.Del("t")
				target := "/"
				if len(q) > 0 {
					target += "?" + q.Encode()
				}
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *server) handleLive(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, s.live.snapshot())
}

func (s *server) handleLiveToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.liveMu.Lock()
	running := s.live != nil
	s.liveMu.Unlock()
	if running {
		s.disableLive()
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	started := s.enableLive()
	writeJSON(w, map[string]interface{}{"enabled": started})
}

func (s *server) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
	go func() {
		time.Sleep(150 * time.Millisecond)
		if s.quit != nil {
			select {
			case s.quit <- struct{}{}:
			default:
			}
		}
	}()
}

func (s *server) handleSysmon(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, sysmonStatus(s.dataDir))
}

func (s *server) handleSysmonInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var out string
	var err error
	if r.FormValue("mode") == "reinstall" {
		s.disableLive()
		out, err = sysmonReinstall(s.dataDir)
	} else {
		out, err = sysmonInstall(s.dataDir)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	started := s.enableLive()
	writeJSON(w, map[string]interface{}{"ok": true, "output": out, "liveStarted": started, "status": sysmonStatus(s.dataDir)})
}

func (s *server) handleSysmonUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	out, err := sysmonUninstall(s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.disableLive()
	writeJSON(w, map[string]interface{}{"ok": true, "output": out, "status": sysmonStatus(s.dataDir)})
}

// handleSysmonArgs 保存附加安装参数，并立即按新参数重新安装。
func (s *server) handleSysmonArgs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	text, err := sysmonSetArgs(s.dataDir, r.FormValue("args"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if v, ok := r.Form["dns"]; ok {
		on := len(v) > 0 && v[0] != "0" && v[0] != "false"
		if err := sysmonSetDNS(s.dataDir, on); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.disableLive()
	out, err := sysmonReinstall(s.dataDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	started := s.enableLive()
	writeJSON(w, map[string]interface{}{"ok": true, "args": text, "output": out,
		"liveStarted": started, "status": sysmonStatus(s.dataDir)})
}

func (s *server) handleSysmonLogSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	gb, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("gb")), 64)
	if err != nil || gb <= 0 {
		http.Error(w, "日志大小无效", http.StatusBadRequest)
		return
	}
	if err := sysmonSetLogSize(int64(gb * float64(int64(1)<<30))); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, sysmonStatus(s.dataDir))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func (s *server) handleMeta(w http.ResponseWriter, r *http.Request) {
	m, err := s.db.Meta()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.live != nil {
		st := s.live.snapshot()
		if st["enabled"].(bool) {
			path, size := sysmonLogFile()
			srcs, _ := m["sources"].([]map[string]interface{})
			found := false
			for _, x := range srcs {
				if x["name"] == liveSource {
					found = true
					x["kind"], x["path"], x["bytes"], x["channel"] = "live", path, size, st["channel"]
				}
			}
			if !found {
				srcs = append(srcs, map[string]interface{}{
					"name": liveSource, "kind": "live", "path": path, "bytes": size,
					"channel": st["channel"], "events": st["total"],
				})
			}
			m["sources"] = srcs
		}
	}
	writeJSON(w, m)
}

func (s *server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sm, err := s.db.Summary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, sm)
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	expr := r.URL.Query().Get("expr")
	switch tab {
	case "procs":
		st, err := s.db.ProcessStats(expr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	case "dns":
		st, err := s.db.DNSStats(expr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	default:
		st, err := s.db.IRStats(expr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	}
}

func intParam(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil && v >= 0 {
		return v
	}
	return def
}

func (s *server) handleConns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := intParam(r, "limit", 200)
	if limit > 2000 {
		limit = 2000
	}
	rows, total, err := s.db.Query(q.Get("expr"), limit, intParam(r, "offset", 0), q.Get("sort"), q.Get("desc") == "1")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rows == nil {
		rows = []*Conn{}
	}
	writeJSON(w, map[string]interface{}{"total": total, "rows": rows})
}

func (s *server) handleProcs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	expr := q.Get("expr")
	limit := intParam(r, "limit", 800)
	if limit > 2000 {
		limit = 2000
	}
	total, err := s.db.CountProcessesFiltered(expr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sortField := q.Get("sort")
	if sortField == "" {
		sortField = "start"
	}
	desc := q.Get("desc") != "0"
	rows, err := s.db.PageProcs(expr, limit, intParam(r, "offset", 0), sortField, desc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rows == nil {
		rows = []procRow{}
	}
	writeJSON(w, map[string]interface{}{"total": total, "rows": rows})
}

func (s *server) handleDNS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	expr := q.Get("expr")
	if expr == "" {
		expr = q.Get("q")
	}
	limit := intParam(r, "limit", 256)
	if limit > 2000 {
		limit = 2000
	}
	total, err := s.db.CountDNSFiltered(expr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sortField := q.Get("sort")
	if sortField == "" {
		sortField = "ts"
	}
	desc := q.Get("desc") != "0"
	rows, err := s.db.PageDNS(expr, limit, intParam(r, "offset", 0), sortField, desc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []*DNSQ{}
	}
	writeJSON(w, map[string]interface{}{"total": total, "rows": rows})
}

func (s *server) handleValues(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	var (
		vals []Count
		err  error
	)
	switch r.URL.Query().Get("tab") {
	case "procs":
		vals, err = s.db.ProcessValues(field, intParam(r, "limit", 10))
	case "dns":
		vals, err = s.db.DNSValues(field, intParam(r, "limit", 10))
	default:
		vals, err = s.db.Values(field, intParam(r, "limit", 10))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"field": field, "values": vals})
}

func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "conns"
	}
	expr := r.URL.Query().Get("expr")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		"attachment; filename=\"n-trace-%s-%s.csv\"", tab, time.Now().Format("20060102-150405")))
	var err error
	switch tab {
	case "procs":
		_, err = exportProcessCSV(s.db, w, expr, s.loc, nil)
	case "dns":
		_, err = exportDNSCSV(s.db, w, expr, s.loc, nil)
	default:
		_, err = exportCSV(s.db, w, expr, s.loc, nil)
	}
	if err != nil {
		appPrintf("导出 CSV 失败: %v", err)
	}
}

func (s *server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Paths) == 0 {
		http.Error(w, "需要 paths 数组", http.StatusBadRequest)
		return
	}
	stats, err := s.db.Import(req.Paths)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, stats)
}

func (s *server) handleSourceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "缺少 name", http.StatusBadRequest)
		return
	}
	conns, dns, err := s.db.DeleteSource(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "name": name, "conns": conns, "dns": dns})
}

// handleUpload 接收浏览器上传的 .evtx（浏览器拿不到本地路径），
// 落到临时目录后走同一套导入管线。
func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Error(w, "解析上传内容失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	dir, err := os.MkdirTemp("", "n-trace-")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(dir)

	var paths []string
	var skipped []string
	sizes := map[string]int64{}
	for _, fh := range r.MultipartForm.File["files"] {
		name := filepath.Base(fh.Filename)
		if !strings.EqualFold(filepath.Ext(name), ".evtx") {
			skipped = append(skipped, name)
			continue
		}
		src, err := fh.Open()
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		dst := filepath.Join(dir, name)
		out, err := os.Create(dst)
		if err != nil {
			src.Close()
			skipped = append(skipped, name)
			continue
		}
		_, err = io.Copy(out, src)
		out.Close()
		src.Close()
		if err != nil {
			skipped = append(skipped, name)
			continue
		}
		if fi, err := os.Stat(dst); err == nil {
			sizes[name] = fi.Size()
		}
		paths = append(paths, dst)
	}
	if len(paths) == 0 {
		http.Error(w, "没有收到 .evtx 文件", http.StatusBadRequest)
		return
	}

	stats, err := s.db.Import(paths)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, name := range stats.Files { // 浏览器上传没有本地路径，只保留大小
		s.db.SetFileInfo(name, "", sizes[name])
	}
	writeJSON(w, map[string]interface{}{
		"files": stats.Files, "conns": stats.Conns, "dns": stats.DNS,
		"events": stats.Events, "took": stats.Took, "skipped": skipped,
	})
}
