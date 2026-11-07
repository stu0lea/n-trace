package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	evtx "www.velocidex.com/golang/evtx"
)

// rawEvent 是从 .evtx 里取出的一条事件，只保留审计需要的部分。
type rawEvent struct {
	EID     string
	Rec     string
	Host    string
	Channel string
	TS      int64 // unix 毫秒，取事件时间（UtcTime 优先）
	F       map[string]string
}

func (e *rawEvent) get(k string) string { return strings.TrimSpace(e.F[k]) }

// readEvtxFile 读取单个 .evtx 的全部事件。
func readEvtxFile(path string) ([]rawEvent, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		return nil, err
	}

	out := make([]rawEvent, 0, 8192)
	for _, c := range chunks {
		recs, err := c.Parse(0)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r == nil || r.Event == nil {
				continue
			}
			evt, ok := r.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}
			e, ok := parseEvent(evt)
			if !ok {
				continue
			}
			e.Rec = strconv.FormatUint(r.Header.RecordID, 10)
			out = append(out, *e)
		}
	}
	return out, nil
}

func parseEvent(evt *ordereddict.Dict) (*rawEvent, bool) {
	root := getDict(evt, "Event")
	if root == nil {
		return nil, false
	}
	system := getDict(root, "System")
	if system == nil {
		return nil, false
	}

	e := &rawEvent{F: map[string]string{}}
	e.EID = strOf(eventID(getVal(system, "EventID")))
	e.Host = strOf(getVal(system, "Computer"))
	e.Channel = strOf(getVal(system, "Channel"))

	if tc := getDict(system, "TimeCreated"); tc != nil {
		if ts, ok := toFloat(getVal(tc, "SystemTime")); ok && ts > 0 {
			e.TS = int64(ts * 1000)
		}
	}

	if d := getDict(root, "EventData"); d != nil {
		for _, k := range d.Keys() {
			v, _ := d.Get(k)
			e.F[k] = strOf(v)
		}
	} else if d := getDict(root, "UserData"); d != nil {
		flattenFields("", d, e.F)
	}

	// Sysmon 的 UtcTime 是事件真正发生时刻，比写日志时间可靠。
	if s := e.F["UtcTime"]; s != "" {
		if t, err := parseSysmonTime(s); err == nil {
			e.TS = t.UnixNano() / 1e6
		}
	}
	return e, e.TS > 0
}

func parseSysmonTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("bad time %q", s)
}

func flattenFields(prefix string, v interface{}, out map[string]string) {
	switch t := v.(type) {
	case *ordereddict.Dict:
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			flattenFields(joinKey(prefix, k), vv, out)
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			flattenFields(joinKey(prefix, k), t[k], out)
		}
	case []interface{}:
		for i, x := range t {
			flattenFields(prefix+"."+strconv.Itoa(i+1), x, out)
		}
	default:
		if prefix == "" {
			return
		}
		out[prefix] = strOf(v)
	}
}

func joinKey(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

func get(v interface{}, key string) (interface{}, bool) {
	switch t := v.(type) {
	case *ordereddict.Dict:
		if t == nil {
			return nil, false
		}
		return t.Get(key)
	case map[string]interface{}:
		x, ok := t[key]
		return x, ok
	}
	return nil, false
}

func getVal(v interface{}, key string) interface{} {
	x, _ := get(v, key)
	return x
}

func getDict(v interface{}, key string) *ordereddict.Dict {
	d, _ := getVal(v, key).(*ordereddict.Dict)
	return d
}

func eventID(v interface{}) interface{} {
	if d, ok := v.(*ordereddict.Dict); ok {
		if x, ok := d.Get("Value"); ok {
			return x
		}
	}
	return v
}

func strOf(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimRight(t, "\x00")
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 9.2e18 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case time.Time:
		return t.UTC().Format("2006-01-02 15:04:05.000")
	}
	return fmt.Sprint(v)
}

func toFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.0000000Z07:00", "2006-01-02 15:04:05.000", "2006-01-02 15:04:05"} {
			if ts, err := time.Parse(layout, t); err == nil {
				return float64(ts.UnixNano()) / 1e9, true
			}
		}
		if f, err := strconv.ParseFloat(t, 10); err == nil {
			return f, true
		}
	}
	return 0, false
}

// expandPaths 展开目录里的 .evtx，支持直接给目录。
func expandPaths(args []string) ([]string, error) {
	var files []string
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if fi.IsDir() {
			entries, err := os.ReadDir(a)
			if err != nil {
				return nil, err
			}
			for _, en := range entries {
				if en.IsDir() || !strings.EqualFold(filepath.Ext(en.Name()), ".evtx") {
					continue
				}
				files = append(files, filepath.Join(a, en.Name()))
			}
			continue
		}
		files = append(files, a)
	}
	sort.Strings(files)
	return files, nil
}
