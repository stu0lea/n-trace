package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"net"
	"strings"

	xdb "github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

//go:embed data/ip2region_v4.xdb.gz
var embeddedGeoGz []byte

type geoDB struct {
	s     *xdb.Searcher
	cache map[string]geoInfo
}

type geoInfo struct {
	Display string
	Country string
}

func openGeo(path string) (*geoDB, error) {
	var buf []byte
	if path != "" {
		b, err := xdb.LoadContentFromFile(path)
		if err != nil {
			return nil, err
		}
		buf = b
	} else {
		zr, err := gzip.NewReader(bytes.NewReader(embeddedGeoGz))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		b, err := io.ReadAll(zr)
		if err != nil {
			return nil, err
		}
		buf = b
	}
	if _, err := xdb.LoadHeaderFromBuff(buf); err != nil {
		return nil, err
	}
	s, err := xdb.NewWithBuffer(xdb.IPv4, buf)
	if err != nil {
		return nil, err
	}
	return &geoDB{s: s, cache: map[string]geoInfo{}}, nil
}

func (g *geoDB) Lookup(ip string) string {
	display, _ := g.LookupInfo(ip)
	return display
}

// LookupInfo 返回可读归属地和两位国家/地区代码（如 CN、US、HK）。
func (g *geoDB) LookupInfo(ip string) (display, country string) {
	if g == nil || g.s == nil || ip == "" {
		return "", ""
	}
	if v, ok := g.cache[ip]; ok {
		return v.Display, v.Country
	}
	info := geoInfo{}
	if net.ParseIP(ip) != nil {
		if raw, err := g.s.Search(ip); err == nil {
			info.Display = formatRegion(raw)
			info.Country = regionCountry(raw)
		}
	}
	g.cache[ip] = info
	return info.Display, info.Country
}

func regionCountry(raw string) string {
	parts := strings.Split(raw, "|")
	if len(parts) < 2 {
		return ""
	}
	last := strings.TrimSpace(parts[len(parts)-1])
	if len(last) == 2 && last == strings.ToUpper(last) &&
		last[0] >= 'A' && last[0] <= 'Z' && last[1] >= 'A' && last[1] <= 'Z' {
		return last
	}
	return ""
}

// formatRegion 把 "中国|河南省|郑州市|联通|CN" 整理成可读归属地。
func formatRegion(raw string) string {
	parts := strings.Split(raw, "|")
	if n := len(parts); n > 1 {
		last := strings.TrimSpace(parts[n-1])
		if len(last) == 2 && last == strings.ToUpper(last) {
			parts = parts[:n-1]
		}
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "0" || strings.EqualFold(p, "reserved") {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == p {
			continue
		}
		out = append(out, p)
	}
	if len(out) > 0 && out[0] == "中国" {
		out = out[1:]
	}
	return strings.Join(out, " ")
}

// isPublicIP 判断是否公网地址。
func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast())
}
