package main

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Conn 是一条网络连接审计记录（Sysmon EID 3，已关联 EID 1 与 EID 22）。
type Conn struct {
	ID      int64             `json:"id"`
	TS      int64             `json:"ts"`
	Host    string            `json:"host"`
	PID     string            `json:"pid"`
	Guid    string            `json:"guid"`
	Image   string            `json:"image"`
	User    string            `json:"user"`
	Proto   string            `json:"proto"`
	SrcIP   string            `json:"srcIp"`
	SrcPort string            `json:"srcPort"`
	DstIP   string            `json:"dstIp"`
	DstPort string            `json:"dstPort"`
	DstHost string            `json:"dstHost"`
	PortNm  string            `json:"portName"`
	Out     bool              `json:"out"`
	V6      bool              `json:"v6"`
	Geo     string            `json:"geo"`
	Country string            `json:"country,omitempty"`
	Public  bool              `json:"public"`
	CmdLine string            `json:"cmdLine"`
	Parent  string            `json:"parent"`
	Hashes  string            `json:"hashes"`
	Integ   string            `json:"integrity"`
	Rule    string            `json:"ruleName"`
	Risk    []string          `json:"risk"`
	Source  string            `json:"source"`
	Raw     map[string]string `json:"raw,omitempty"`
}

// DNSQ 是一条 DNS 查询（Sysmon EID 22）。
type DNSQ struct {
	TS      int64             `json:"ts"`
	Host    string            `json:"host"`
	PID     string            `json:"pid"`
	Guid    string            `json:"guid"`
	Image   string            `json:"image"`
	User    string            `json:"user"`
	Query   string            `json:"query"`
	Results string            `json:"results"`
	Status  string            `json:"status"`
	Geo     string            `json:"geo"`
	Country string            `json:"country"`
	Risk    []string          `json:"risk"`
	Rule    string            `json:"ruleName"`
	Raw     map[string]string `json:"raw,omitempty"`
}

// ProcessEvent 是一条 Sysmon 进程创建/结束事件（EID 1/5）。
type ProcessEvent struct {
	EventID       int
	TS            int64
	Host          string
	Guid          string
	PID           string
	Image         string
	CmdLine       string
	User          string
	Integrity     string
	Hashes        string
	ParentGuid    string
	ParentPID     string
	ParentImage   string
	ParentCmdLine string
	Rule          string
	Raw           map[string]string
	Source        string
}

type ipDNS struct {
	ts     int64
	domain string
}

type procInfo struct {
	Image, CmdLine, Parent, Hashes, User, Integ string
}

func nearestDomain(l []ipDNS, ts int64) string {
	best, delta := "", int64(1<<62)
	for _, x := range l {
		d := x.ts - ts
		if d < 0 {
			d = -d
		}
		if d < delta {
			delta, best = d, x.domain
		}
	}
	return best
}

func connFromEvent(e *rawEvent, geo *geoDB) *Conn {
	dst := e.get("DestinationIp")
	if dst == "" {
		return nil
	}
	c := &Conn{
		TS:      e.TS,
		Host:    e.Host,
		PID:     e.get("ProcessId"),
		Guid:    e.get("ProcessGuid"),
		Image:   e.get("Image"),
		User:    e.get("User"),
		Proto:   strings.ToLower(e.get("Protocol")),
		SrcIP:   e.get("SourceIp"),
		SrcPort: e.get("SourcePort"),
		DstIP:   dst,
		DstPort: e.get("DestinationPort"),
		DstHost: e.get("DestinationHostname"),
		PortNm:  e.get("DestinationPortName"),
		Out:     strings.EqualFold(e.get("Initiated"), "true"),
		V6:      strings.EqualFold(e.get("DestinationIsIpv6"), "true"),
		Rule:    e.get("RuleName"),
	}
	if c.Proto == "" {
		c.Proto = "tcp"
	}
	c.Public = isPublicIP(dst)
	if c.Public {
		c.Geo, c.Country = geo.LookupInfo(dst)
	}
	return c
}

func dnsFromEvent(e *rawEvent) *DNSQ {
	q := e.get("QueryName")
	if q == "" {
		return nil
	}
	return &DNSQ{
		TS: e.TS, Host: e.Host, PID: e.get("ProcessId"), Guid: e.get("ProcessGuid"),
		Image: e.get("Image"), User: e.get("User"), Query: q,
		Results: e.get("QueryResults"), Status: e.get("QueryStatus"), Rule: e.get("RuleName"),
	}
}

func processEventFromRaw(e *rawEvent) *ProcessEvent {
	eventID := 0
	switch e.EID {
	case "1":
		eventID = 1
	case "5":
		eventID = 5
	default:
		return nil
	}
	guid := e.get("ProcessGuid")
	if guid == "" {
		return nil
	}
	return &ProcessEvent{
		EventID: eventID, TS: e.TS, Host: e.Host, Guid: guid, PID: e.get("ProcessId"),
		Image: e.get("Image"), CmdLine: e.get("CommandLine"), User: e.get("User"),
		Integrity: e.get("IntegrityLevel"), Hashes: e.get("Hashes"),
		ParentGuid: e.get("ParentProcessGuid"), ParentPID: e.get("ParentProcessId"),
		ParentImage: e.get("ParentImage"), ParentCmdLine: e.get("ParentCommandLine"),
		Rule: e.get("RuleName"), Raw: e.F,
	}
}

var ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// dnsIPs 从 QueryResults 里提取 IPv4，兼容两种格式：
//
//	180.101.50.242;
//	type:  5 www.a.com;type:  1 180.101.50.242;
func dnsIPs(results string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range ipv4Re.FindAllString(results, -1) {
		if net.ParseIP(m) == nil || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

const (
	dnsRiskForeign = "D1"
	dnsRiskFailed  = "D2"
	dnsRiskEmpty   = "D3"
)

var dnsRuleText = map[string]string{
	dnsRiskForeign: "解析境外 IP",
	dnsRiskFailed:  "DNS 查询失败",
	dnsRiskEmpty:   "无解析结果",
}

func dnsGeoRisk(results, status string, geo *geoDB) (display, country, risk string) {
	ips := dnsIPs(results)
	displays := []string{}
	countries := []string{}
	seenDisplay := map[string]bool{}
	seenCountry := map[string]bool{}
	foreign := false
	for _, ip := range ips {
		if !isPublicIP(ip) {
			continue
		}
		d, c := geo.LookupInfo(ip)
		if d != "" && !seenDisplay[d] {
			seenDisplay[d] = true
			displays = append(displays, d)
		}
		if c != "" && !seenCountry[c] {
			seenCountry[c] = true
			countries = append(countries, c)
		}
		if c != "" && !strings.EqualFold(c, "CN") {
			foreign = true
		}
	}
	risks := []string{}
	if foreign {
		risks = append(risks, dnsRiskForeign)
	}
	if status != "" && status != "0" {
		risks = append(risks, dnsRiskFailed)
	} else if len(ips) == 0 {
		risks = append(risks, dnsRiskEmpty)
	}
	return strings.Join(displays, " / "), strings.Join(countries, "/"), strings.Join(risks, " ")
}

// ---------------------------------------------------------------- 风险规则

var webPorts = map[string]bool{"80": true, "443": true, "8080": true, "8443": true, "8000": true, "8888": true}

var browserExe = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "iexplore.exe": true,
	"opera.exe": true, "brave.exe": true, "360se.exe": true, "360chrome.exe": true,
	"qqbrowser.exe": true, "sogouexplorer.exe": true, "wechatbrowser.exe": true,
	"weixin.exe": true, "wechat.exe": true, "code.exe": true, "msedgewebview2.exe": true,
}

var safePorts = map[string]bool{
	"53": true, "80": true, "123": true, "443": true, "8080": true, "8443": true,
}

func exeName(p string) string {
	p = strings.ReplaceAll(p, "/", "\\")
	if i := strings.LastIndex(p, "\\"); i >= 0 {
		return strings.ToLower(p[i+1:])
	}
	return strings.ToLower(p)
}

func judge(c *Conn) []string {
	var r []string
	if !c.Public {
		return r
	}
	exe := exeName(c.Image)
	if c.Out && c.DstPort != "" && !safePorts[c.DstPort] {
		r = append(r, "R1")
	}
	if webPorts[c.DstPort] && !browserExe[exe] && !strings.HasPrefix(exe, "svchost") && exe != "system" {
		r = append(r, "R2")
	}
	low := strings.ToLower(c.Image)
	for _, bad := range []string{"\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\windows\\temp\\"} {
		if strings.Contains(low, bad) {
			r = append(r, "R3")
			break
		}
	}
	if c.Out && c.DstHost == "" {
		r = append(r, "R4")
	}
	if c.Public && c.Country != "" && !strings.EqualFold(c.Country, "CN") {
		r = append(r, "R6")
	}
	return r
}

func markFanout(conns []*Conn) {
	byProc := map[string][]*Conn{}
	for _, c := range conns {
		if c.Public && c.Out {
			byProc[c.Guid] = append(byProc[c.Guid], c)
		}
	}
	for _, l := range byProc {
		sort.SliceStable(l, func(i, j int) bool { return l[i].TS < l[j].TS })
		start, lastMark := 0, int64(-1<<62)
		for i := range l {
			for start < i && l[i].TS-l[start].TS > 5*60*1000 {
				start++
			}
			ips := map[string]bool{}
			for j := start; j <= i; j++ {
				ips[l[j].DstIP] = true
			}
			if len(ips) >= 20 && l[i].TS-lastMark > 5*60*1000 {
				addRisk(l[i], "R5")
				lastMark = l[i].TS
			}
		}
	}
}

func addRisk(c *Conn, r string) {
	for _, x := range c.Risk {
		if x == r {
			return
		}
	}
	c.Risk = append(c.Risk, r)
}

func idOf(c *Conn) string { return fmt.Sprintf("%d", c.ID) }
