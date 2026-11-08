//go:build windows

package main

import (
	"strconv"
	"testing"
	"time"
)

func TestHotCacheKeyDistinguishesTabFieldAndNetOnly(t *testing.T) {
	same := []struct {
		a, b string
	}{
		{hotCacheKey(0, "image", true), hotCacheKey(0, "image", true)},
		{hotCacheKey(1, "image", false), hotCacheKey(1, "image", false)},
	}
	for _, p := range same {
		if p.a != p.b {
			t.Fatalf("相同参数应生成相同键：%s != %s", p.a, p.b)
		}
	}
	keys := map[string]bool{}
	distinct := []string{
		hotCacheKey(0, "image", true),
		hotCacheKey(1, "image", true),
		hotCacheKey(2, "image", true),
		hotCacheKey(0, "user", true),
		hotCacheKey(0, "image", false),
	}
	for _, k := range distinct {
		if keys[k] {
			t.Fatalf("不同参数不应生成相同键：%s", k)
		}
		keys[k] = true
	}
}

func TestHotEntryFreshTTL(t *testing.T) {
	now := time.Now()
	fresh := hotEntry{at: now.Add(-30 * time.Second)}
	if !hotEntryFresh(fresh, now) {
		t.Fatal("30 秒前的条目应视为新鲜")
	}
	stale := hotEntry{at: now.Add(-2 * hotCacheTTL)}
	if hotEntryFresh(stale, now) {
		t.Fatal("超过 TTL 的条目不应视为新鲜")
	}
	boundary := hotEntry{at: now.Add(-hotCacheTTL)}
	if hotEntryFresh(boundary, now) {
		t.Fatal("恰好等于 TTL 的条目不应视为新鲜")
	}
}

// TestApplyHotValuesFiltersBlanksAndLimits 验证热词填充逻辑：
// 跳过空白键、最多保留 10 个、按顺序填 counts。
func TestApplyHotValuesFiltersBlanksAndLimits(t *testing.T) {
	a := &nativeApp{hotCache: map[string]hotEntry{}}
	vals := make([]Count, 0, 15)
	for i := 0; i < 15; i++ {
		vals = append(vals, Count{Key: "key-" + strconv.Itoa(i), N: 100 - i})
	}
	// 空白键应被跳过，不占 10 个名额。
	vals[3].Key = "   "
	vals = append(vals, Count{Key: "tail", N: 1})

	a.applyHotValues(vals)
	if len(a.hotValues) != 10 || len(a.hotCounts) != 10 {
		t.Fatalf("应填充 10 个热词，实际 %d/%d", len(a.hotValues), len(a.hotCounts))
	}
	for _, k := range a.hotValues {
		if k == "   " || k == "" {
			t.Fatal("空白键不应出现在热词里")
		}
	}
	// key-3 为空白被跳过，第 10 个应是 key-10（索引 0..15 中第 10 个非空项）。
	if a.hotValues[9] != "key-10" {
		t.Fatalf("第 10 个热词应为 key-10，实际 %s", a.hotValues[9])
	}
	if a.hotCounts[0] != 100 {
		t.Fatalf("counts 应与热词一一对应，实际 %d", a.hotCounts[0])
	}

	// 全部为空时应清空现有热词。
	a.applyHotValues([]Count{{Key: "  ", N: 5}})
	if len(a.hotValues) != 0 || len(a.hotCounts) != 0 {
		t.Fatalf("全空白输入应清空热词，实际 %v", a.hotValues)
	}
}
