package main

import (
	"bytes"
	"encoding/xml"
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
}

func (s *LiveStats) setMode(mode, channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Enabled, s.Mode, s.Channel = true, mode, channel
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now()
	}
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

func (s *LiveStats) snapshot() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"enabled": s.Enabled, "connected": s.Connected, "mode": s.Mode,
		"channel": s.Channel, "total": s.Total, "lastTs": s.LastTS,
		"lastError": s.LastError, "startedAt": s.StartedAt.UnixMilli(),
	}
}

// ---------------------------------------------------------------- 采集循环

type liveConfig struct {
	Channel  string
	Interval time.Duration
	Warmup   int // 启动时补读的最近事件数（进程创建/DNS），用于补齐进程与域名信息
}

// startLive 轮询事件日志，把新事件增量入库。
func startLive(db *DB, st *LiveStats, cfg liveConfig, logf func(string, ...interface{})) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Channel == "" {
		cfg.Channel = defaultChannel
	}
	st.setMode("poll", cfg.Channel)

	if err := liveSupported(); err != nil {
		st.fail(err.Error())
		logf("实时采集不可用: %v", err)
		return
	}

	last, err := liveLatestID(cfg.Channel)
	if err != nil {
		st.fail(err.Error())
		logf("读取日志通道失败（需要管理员权限）: %v", err)
	} else {
		st.setConnected(true, "")
		logf("实时采集已启动：%s（从记录 %d 之后开始）", cfg.Channel, last)
	}

	if cfg.Warmup > 0 {
		if evs := liveWarmup(cfg.Channel, cfg.Warmup); len(evs) > 0 {
			if _, _, err := db.Ingest(evs, liveSource); err != nil {
				logf("补读最近事件失败: %v", err)
			}
		}
	}

	for {
		time.Sleep(cfg.Interval)
		if !st.active() {
			return
		}
		evs, err := liveQuery(cfg.Channel, last, 500)
		if err != nil {
			st.fail(err.Error())
			continue
		}
		fresh := make([]rawEvent, 0, len(evs))
		for _, e := range evs {
			if rec, err := strconv.ParseInt(e.Rec, 10, 64); err == nil && rec > last {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			st.setConnected(true, "")
			continue
		}
		sort.Slice(fresh, func(i, j int) bool {
			a, _ := strconv.ParseInt(fresh[i].Rec, 10, 64)
			b, _ := strconv.ParseInt(fresh[j].Rec, 10, 64)
			return a < b
		})
		if _, _, err := db.Ingest(fresh, liveSource); err != nil {
			st.fail("入库失败: " + err.Error())
			continue
		}
		if rec, err := strconv.ParseInt(fresh[len(fresh)-1].Rec, 10, 64); err == nil {
			last = rec
		}
		st.add(len(fresh), fresh[len(fresh)-1].TS)
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

// parseXMLEvents 解析 wevtutil/EvtRender 输出的一个或多个 <Event> 文档。
func parseXMLEvents(data []byte) []rawEvent {
	out := []rawEvent{}
	dec := xml.NewDecoder(bytes.NewReader(normalizeXML(data)))
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var x xmlEvent
		if err := dec.DecodeElement(&x, &se); err != nil {
			continue
		}
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
			continue
		}
		out = append(out, *e)
	}
	return out
}

func stripBOM(b []byte) []byte { return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) }
