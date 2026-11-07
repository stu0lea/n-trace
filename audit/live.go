package main

import (
	"bytes"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// 默认实时采集的日志通道。
const defaultChannel = "Microsoft-Windows-Sysmon/Operational"

// liveSource 实时数据在文件清单里的名称。
const liveSource = "实时采集"

// LiveStats 记录实时采集状态，供界面展示。
type LiveStats struct {
	mu        sync.RWMutex
	Enabled   bool
	Connected bool
	Mode      string
	Channel   string
	Total     int64
	LastTS    int64
	LastError string
	StartedAt time.Time
	Reading   bool
	LastBatch int
	LastRead  time.Time
	LastTook  time.Duration
	stopped   bool
}

func (s *LiveStats) setMode(mode, channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Mode, s.Channel = mode, channel
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now()
	}
}

func (s *LiveStats) begin(mode, channel string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.Enabled = true
	s.Mode, s.Channel = mode, channel
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now()
	}
	return true
}

func (s *LiveStats) setConnected(ok bool, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Connected = ok
	s.LastError = errMsg
}

func (s *LiveStats) fail(msg string) { s.setConnected(false, msg) }

// stop 停止采集循环，并让界面显示为未开启。
func (s *LiveStats) stop(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Enabled = false
	s.Connected = false
	s.LastError = reason
	s.stopped = true
}

func (s *LiveStats) active() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Enabled
}

func (s *LiveStats) add(n int, ts int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Total += int64(n)
	if ts > s.LastTS {
		s.LastTS = ts
	}
	s.Connected = true
	s.LastError = ""
}

func (s *LiveStats) setReading(on bool, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Reading = on
	s.LastRead = time.Now()
	if !on {
		s.LastBatch = n
	}
}

func (s *LiveStats) setTook(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastTook = d
}

func (s *LiveStats) total() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Total
}

func (s *LiveStats) snapshot() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"enabled": s.Enabled, "connected": s.Connected, "mode": s.Mode,
		"channel": s.Channel, "total": s.Total, "lastTs": s.LastTS,
		"lastError": s.LastError, "startedAt": s.StartedAt.UnixMilli(),
		"reading": s.Reading, "lastBatch": s.LastBatch, "lastRead": s.LastRead.UnixMilli(),
		"lastTook": int64(s.LastTook / time.Millisecond),
	}
}

const liveCheckpointName = "live-last-id.txt"

func readLiveCheckpoint(dir string) (int64, error) {
	if dir == "" {
		return 0, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, liveCheckpointName))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

func writeLiveCheckpoint(dir string, id int64) {
	if dir == "" || id <= 0 {
		return
	}
	path := filepath.Join(dir, liveCheckpointName)
	data := []byte(strconv.FormatInt(id, 10) + "\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err == nil {
		if os.Rename(tmp, path) == nil {
			return
		}
		_ = os.Remove(tmp)
	}
	// 极少数环境不允许覆盖重命名时，直接写回，保证断点仍能推进。
	_ = os.WriteFile(path, data, 0o644)
}

// selectLiveStart 只接受落在当前日志范围内的断点。
// 断点缺失、为 0 或大于最新记录号时，才从当前日志起点开始补读。
func selectLiveStart(checkpoint, latest int64) int64 {
	if checkpoint <= 0 || latest <= 0 || checkpoint > latest {
		return 0
	}
	return checkpoint
}

func liveCanceled(st *LiveStats, stop <-chan struct{}) bool {
	if !st.active() {
		return true
	}
	if stop == nil {
		return false
	}
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

// backfillLive 从检查点开始按批次补读全部历史事件，直到追上当前日志末尾。
func backfillLive(db *DB, st *LiveStats, cfg liveConfig, start int64, logf func(string, ...interface{})) (int64, error) {
	last := start
	for {
		if liveCanceled(st, cfg.Stop) {
			return last, nil
		}
		st.setReading(true, 0)
		evs, err := liveQueryAfter(cfg.Channel, last, 2000)
		if err != nil {
			st.setReading(false, 0)
			return last, err
		}
		if liveCanceled(st, cfg.Stop) {
			st.setReading(false, 0)
			return last, nil
		}
		fresh := make([]rawEvent, 0, len(evs))
		for _, e := range evs {
			if rec, err := strconv.ParseInt(e.Rec, 10, 64); err == nil && rec > last {
				fresh = append(fresh, e)
			}
		}
		st.setReading(false, len(fresh))
		if len(fresh) == 0 {
			return last, nil
		}
		sort.Slice(fresh, func(i, j int) bool {
			a, _ := strconv.ParseInt(fresh[i].Rec, 10, 64)
			b, _ := strconv.ParseInt(fresh[j].Rec, 10, 64)
			return a < b
		})
		if liveCanceled(st, cfg.Stop) {
			return last, nil
		}
		if _, _, err := db.Ingest(fresh, liveSource); err != nil {
			return last, err
		}
		if rec, err := strconv.ParseInt(fresh[len(fresh)-1].Rec, 10, 64); err == nil {
			last = rec
		}
		writeLiveCheckpoint(cfg.DataDir, last)
		st.add(len(fresh), fresh[len(fresh)-1].TS)
		logf("补读进度：已到记录 %d，本批 %d 条", last, len(fresh))
		select {
		case <-time.After(30 * time.Millisecond):
		case <-cfg.Stop:
			return last, nil
		}
	}
}

// ---------------------------------------------------------------- 采集循环

type liveConfig struct {
	Channel    string
	Interval   time.Duration
	DataDir    string
	OnBatch    func(int, time.Duration)
	IntervalFn func() time.Duration
	Wake       <-chan struct{}
	Stop       <-chan struct{}
}

// startLive 轮询事件日志，把新事件增量入库。
func startLive(db *DB, st *LiveStats, cfg liveConfig, logf func(string, ...interface{})) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Channel == "" {
		cfg.Channel = defaultChannel
	}
	if !st.begin("poll", cfg.Channel) {
		return
	}

	if err := liveSupported(); err != nil {
		st.fail(err.Error())
		logf("实时采集不可用: %v", err)
		return
	}

	start, err := readLiveCheckpoint(cfg.DataDir)
	if err != nil {
		start = 0
	}
	latest, err := liveLatestID(cfg.Channel)
	if err != nil {
		st.fail(err.Error())
		logf("读取日志通道失败（需要管理员权限）: %v", err)
		return
	}
	checkpoint := start
	start = selectLiveStart(start, latest)
	if start == 0 {
		if checkpoint > 0 && latest > 0 && checkpoint > latest {
			logf("上次断点 %d 超过当前最新记录 %d，日志可能已轮转，开始补读当前日志中的全部 Sysmon 事件",
				checkpoint, latest)
		} else {
			logf("未找到可用断点，开始补读当前日志中的全部 Sysmon 事件")
		}
	} else {
		logf("从上次断点 %d 之后补读关闭期间的新事件", start)
	}
	st.setMode("backfill", cfg.Channel)
	beforeTotal := st.total()
	backfillStart := time.Now()
	last, err := backfillLive(db, st, cfg, start, logf)
	if err != nil {
		st.fail(err.Error())
		logf("补读历史日志失败: %v", err)
		return
	}
	if liveCanceled(st, cfg.Stop) {
		return
	}
	logf("补读完成：记录 %d -> %d，读取 %d 条，耗时 %s",
		start, last, st.total()-beforeTotal, time.Since(backfillStart).Round(time.Millisecond))
	st.setMode("poll", cfg.Channel)
	st.setConnected(true, "")
	logf("实时采集已启动：%s（从记录 %d 之后开始）", cfg.Channel, last)
	if cfg.OnBatch != nil {
		cfg.OnBatch(0, 0)
	}

	lastErrLog := time.Time{}
	lastHeartbeat := time.Now()
	heartbeatRead := 0
	for {
		wait := cfg.Interval
		if cfg.IntervalFn != nil {
			wait = cfg.IntervalFn()
		}
		if wait < time.Second {
			wait = time.Second
		}
		if cfg.Wake != nil {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-cfg.Wake:
				if !timer.Stop() {
					<-timer.C
				}
				continue
			case <-cfg.Stop:
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
		} else {
			time.Sleep(wait)
		}
		if liveCanceled(st, cfg.Stop) {
			return
		}
		batchStart := time.Now()
		st.setReading(true, 0)
		evs, err := liveQuery(cfg.Channel, last, 500)
		if err != nil {
			st.setReading(false, 0)
			st.fail(err.Error())
			if time.Since(lastErrLog) > 30*time.Second {
				logf("实时读取失败: %v", err)
				lastErrLog = time.Now()
			}
			continue
		}
		fresh := make([]rawEvent, 0, len(evs))
		for _, e := range evs {
			if rec, err := strconv.ParseInt(e.Rec, 10, 64); err == nil && rec > last {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			st.setTook(time.Since(batchStart))
			st.setReading(false, 0)
			st.setConnected(true, "")
			if time.Since(lastHeartbeat) >= 60*time.Second {
				logf("实时心跳：近 %s 读取 0 条，累计读取 %d 条，当前记录 %d",
					time.Since(lastHeartbeat).Round(time.Second), st.total(), last)
				lastHeartbeat = time.Now()
				heartbeatRead = 0
			}
			continue
		}
		sort.Slice(fresh, func(i, j int) bool {
			a, _ := strconv.ParseInt(fresh[i].Rec, 10, 64)
			b, _ := strconv.ParseInt(fresh[j].Rec, 10, 64)
			return a < b
		})
		if _, _, err := db.Ingest(fresh, liveSource); err != nil {
			st.setReading(false, len(fresh))
			st.fail("入库失败: " + err.Error())
			continue
		}
		if rec, err := strconv.ParseInt(fresh[len(fresh)-1].Rec, 10, 64); err == nil {
			last = rec
		}
		// 实时批次也必须推进断点，否则关闭后会从上次启动位置重复补读。
		writeLiveCheckpoint(cfg.DataDir, last)
		st.setReading(false, len(fresh))
		st.setTook(time.Since(batchStart))
		st.add(len(fresh), fresh[len(fresh)-1].TS)
		heartbeatRead += len(fresh)
		logf("实时读取：%d 条（记录 %s-%s）", len(fresh), fresh[0].Rec, fresh[len(fresh)-1].Rec)
		if cfg.OnBatch != nil {
			cfg.OnBatch(len(fresh), time.Since(batchStart))
		}
		if time.Since(lastHeartbeat) >= 60*time.Second {
			logf("实时心跳：近 %s 读取 %d 条，累计读取 %d 条，当前记录 %d",
				time.Since(lastHeartbeat).Round(time.Second), heartbeatRead, st.total(), last)
			lastHeartbeat = time.Now()
			heartbeatRead = 0
		}
	}
}

// ---------------------------------------------------------------- XML 解析

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID struct {
			Value string `xml:",chardata"`
		} `xml:"EventID"`
		EventRecordID struct {
			Value string `xml:",chardata"`
		} `xml:"EventRecordID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
		Channel  string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

var xmlDecl = regexp.MustCompile(`(?is)<\?xml[^>]*\?>`)

// normalizeXML 统一成 UTF-8 并去掉 XML 声明，避免 wevtutil 的编码声明让解析器报错。
func normalizeXML(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if len(b) >= 2 {
		switch {
		case b[0] == 0xFF && b[1] == 0xFE:
			b = []byte(decodeUTF16(b[2:], false))
		case b[0] == 0xFE && b[1] == 0xFF:
			b = []byte(decodeUTF16(b[2:], true))
		case b[0] == '<' && b[1] == 0:
			b = []byte(decodeUTF16(b, false))
		case b[0] == 0 && b[1] == '<':
			b = []byte(decodeUTF16(b, true))
		}
	}
	return xmlDecl.ReplaceAll(b, nil)
}

func decodeUTF16(b []byte, bigEndian bool) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return string(utf16.Decode(u))
}

// parseXMLEvents 逐条解析 wevtutil 输出的 <Event> 文档。
// wevtutil 会把多个根节点直接拼接，单条损坏时不能拖垮整批。
func parseXMLEvents(data []byte) []rawEvent {
	data = normalizeXML(data)
	const (
		startTag = "<Event"
		endTag   = "</Event>"
	)
	out := []rawEvent{}
	for {
		start := bytes.Index(data, []byte(startTag))
		if start < 0 {
			break
		}
		end := bytes.Index(data[start:], []byte(endTag))
		if end < 0 {
			break
		}
		end += len(endTag)
		chunk := data[start : start+end]
		data = data[start+end:]

		var x xmlEvent
		if err := xml.Unmarshal(chunk, &x); err != nil {
			// wevtutil 偶尔会把非 UTF-8 字节写进 CommandLine，先替换为
			// U+FFFD 再解析，保留事件而不是整条丢弃。
			fixed := bytes.ToValidUTF8(chunk, []byte("\uFFFD"))
			if err2 := xml.Unmarshal(fixed, &x); err2 != nil {
				if rec := recordIDFromChunk(chunk); rec != "" {
					out = append(out, rawEvent{Rec: rec})
				}
				continue
			}
		}
		if e := eventFromXML(&x); e != nil {
			out = append(out, *e)
		}
	}
	return out
}

var eventRecordIDRe = regexp.MustCompile(`(?is)<EventRecordID>\s*(\d+)\s*</EventRecordID>`)

func recordIDFromChunk(chunk []byte) string {
	if m := eventRecordIDRe.FindSubmatch(chunk); m != nil {
		return string(m[1])
	}
	return ""
}

func eventFromXML(x *xmlEvent) *rawEvent {
	e := &rawEvent{F: map[string]string{}}
	e.EID = strings.TrimSpace(x.System.EventID.Value)
	e.Rec = strings.TrimSpace(x.System.EventRecordID.Value)
	e.Host = strings.TrimSpace(x.System.Computer)
	e.Channel = strings.TrimSpace(x.System.Channel)
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(x.System.TimeCreated.SystemTime)); err == nil {
		e.TS = t.UnixNano() / 1e6
	}
	for _, d := range x.EventData.Data {
		e.F[d.Name] = strings.TrimRight(d.Value, "\x00")
	}
	if s := e.F["UtcTime"]; s != "" {
		if t, err := parseSysmonTime(s); err == nil {
			e.TS = t.UnixNano() / 1e6
		}
	}
	if e.EID == "" || e.TS == 0 {
		return nil
	}
	return e
}

func stripBOM(b []byte) []byte { return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) }
