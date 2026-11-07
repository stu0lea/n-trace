package main

import (
	"strings"
	"testing"
)

func TestJudgeForeignIP(t *testing.T) {
	c := &Conn{
		Public: true, Country: "US", Out: true, DstPort: "443",
		Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`, DstHost: "example.com",
	}
	if !hasRisk(judge(c), "R6") {
		t.Fatal("foreign public IP should hit R6")
	}
	c.Country = "CN"
	if hasRisk(judge(c), "R6") {
		t.Fatal("domestic IP should not hit R6")
	}
}

func TestRegionCountry(t *testing.T) {
	if got := regionCountry("中国|河南省|郑州市|联通|CN"); got != "CN" {
		t.Fatalf("country = %q", got)
	}
	if got := regionCountry("美国|加利福尼亚州|洛杉矶|0|US"); got != "US" {
		t.Fatalf("country = %q", got)
	}
}

func TestDNSGeoRisk(t *testing.T) {
	geo, err := openGeo("")
	if err != nil {
		t.Fatal(err)
	}
	display, country, risk := dnsGeoRisk("8.8.8.8", "0", geo)
	if display == "" || country == "" || !hasRisk(strings.Fields(risk), dnsRiskForeign) {
		t.Fatalf("境外解析识别失败: display=%q country=%q risk=%q", display, country, risk)
	}
	if _, _, risk := dnsGeoRisk("", "9002", nil); !hasRisk(strings.Fields(risk), dnsRiskFailed) {
		t.Fatalf("查询失败风险缺失: %q", risk)
	}
	if _, _, risk := dnsGeoRisk("", "0", nil); !hasRisk(strings.Fields(risk), dnsRiskEmpty) {
		t.Fatalf("无解析结果风险缺失: %q", risk)
	}
}

func hasRisk(risks []string, want string) bool {
	for _, r := range risks {
		if r == want {
			return true
		}
	}
	return false
}
