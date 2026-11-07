//go:build windows

package main

import (
	"sync"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	"github.com/rodrigocfd/windigo/wstr"
)

const (
	virtualBlockSize  = 256
	virtualCacheLimit = 16
)

// sharedVirtualTable is the common owner-data implementation used by all tabs.
type sharedVirtualTable[T any] struct {
	app  *nativeApp
	lv   *ui.ListView
	kind string

	snapshotFn func(string) (int64, error)
	countFn    func(string, int64) (int, error)
	pageFn     func(string, int, int, string, bool, int64) ([]T, error)
	cellFn     func(T, int, int) string
	tipFn      func(T, int, int) string

	mu        sync.Mutex
	gen       int
	expr      string
	sortField string
	desc      bool
	total     int
	snapshot  int64
	cache     map[int][]T
	order     []int
	loading   map[int]bool
	dirty     bool
}

func newSharedVirtualTable[T any](
	app *nativeApp,
	lv *ui.ListView,
	kind string,
	snapshotFn func(string) (int64, error),
	countFn func(string, int64) (int, error),
	pageFn func(string, int, int, string, bool, int64) ([]T, error),
	cellFn func(T, int, int) string,
	tipFn func(T, int, int) string,
) *sharedVirtualTable[T] {
	t := &sharedVirtualTable[T]{
		app: app, lv: lv, kind: kind,
		snapshotFn: snapshotFn, countFn: countFn, pageFn: pageFn,
		cellFn: cellFn, tipFn: tipFn,
		cache: map[int][]T{}, loading: map[int]bool{},
	}
	t.bind()
	return t
}

func (t *sharedVirtualTable[T]) bind() {
	t.lv.On().LvnGetDispInfo(t.onGetDispInfo)
	t.lv.On().LvnGetInfoTip(t.onGetInfoTip)
	t.lv.On().LvnEndScroll(func(_ *win.NMLVSCROLL) {
		if t.isDirty() && t.topIndex() == 0 {
			t.reload(t.currentExpr(), t.currentSort(), t.currentDesc())
		}
	})
}

func (t *sharedVirtualTable[T]) onGetDispInfo(p *win.NMLVDISPINFO) {
	if p.Item.Mask&co.LVIF_TEXT == 0 {
		return
	}
	row, sub := int(p.Item.IItem), int(p.Item.ISubItem)
	if row < 0 || row >= t.totalCount() || sub < 0 || sub >= t.lv.ColCount() {
		return
	}
	if value, ok := t.row(row); ok {
		wstr.EncodeToBuf(p.Item.PszText(), t.cellFn(value, sub, row))
		return
	}
	wstr.EncodeToBuf(p.Item.PszText(), "…")
	t.ensureBlock(row / virtualBlockSize)
}

func (t *sharedVirtualTable[T]) onGetInfoTip(p *win.NMLVGETINFOTIP) {
	value, ok := t.row(int(p.IItem))
	if !ok || p.ISubItem < 0 || int(p.ISubItem) >= t.lv.ColCount() {
		return
	}
	fn := t.tipFn
	if fn == nil {
		fn = t.cellFn
	}
	wstr.EncodeToBuf(p.PszText(), fn(value, int(p.ISubItem), int(p.IItem)))
}

func (t *sharedVirtualTable[T]) refresh(expr, sortField string, desc bool) {
	t.mu.Lock()
	same := t.expr == expr && t.sortField == sortField && t.desc == desc
	t.mu.Unlock()
	if !same || t.topIndex() == 0 {
		t.reload(expr, sortField, desc)
		return
	}
	t.mu.Lock()
	t.dirty = true
	t.mu.Unlock()
	t.refreshCount()
}

func (t *sharedVirtualTable[T]) reload(expr, sortField string, desc bool) {
	hOrigin := listHOrigin(t.lv)
	t.mu.Lock()
	t.gen++
	gen := t.gen
	t.expr, t.sortField, t.desc = expr, sortField, desc
	t.dirty = false
	t.mu.Unlock()

	t.lv.SetRedraw(false)
	t.app.setStatus("正在加载" + t.kind + "…")
	go func() {
		snapshot, err := t.snapshotFn(expr)
		var total int
		if err == nil {
			total, err = t.countFn(expr, snapshot)
		}
		var first []T
		if err == nil {
			first, err = t.pageFn(expr, virtualBlockSize, 0, sortField, desc, snapshot)
		}
		t.app.wnd.UiThread(func() {
			if !t.isCurrent(gen) {
				return
			}
			if err != nil {
				t.lv.SetRedraw(true)
				t.lv.Hwnd().InvalidateRect(nil, false)
				t.app.setStatus(t.kind + "加载失败：" + err.Error())
				return
			}
			t.mu.Lock()
			t.total = total
			t.snapshot = snapshot
			t.cache = map[int][]T{0: first}
			t.order = []int{0}
			t.loading = map[int]bool{}
			t.dirty = false
			t.mu.Unlock()
			t.lv.Hwnd().SendMessage(co.LVM_SETITEMCOUNT, win.WPARAM(total), 0)
			restoreListHOrigin(t.lv, hOrigin)
			if total > 0 {
				t.lv.Hwnd().SendMessage(co.LVM_ENSUREVISIBLE, 0, 1)
			}
			t.lv.SetRedraw(true)
			t.lv.Hwnd().InvalidateRect(nil, false)
			t.lv.Hwnd().UpdateWindow()
			t.app.setStatus("就绪")
		})
	}()
}

func (t *sharedVirtualTable[T]) refreshCount() {
	hOrigin := listHOrigin(t.lv)
	oldTop := t.topIndex()
	t.mu.Lock()
	gen, expr, snapshot, oldTotal := t.gen, t.expr, t.snapshot, t.total
	t.mu.Unlock()
	go func() {
		total, err := t.countFn(expr, snapshot)
		if err != nil {
			return
		}
		t.app.wnd.UiThread(func() {
			if !t.isCurrent(gen) {
				return
			}
			t.mu.Lock()
			old := t.total
			t.total = total
			t.mu.Unlock()
			if total != old {
				withListRedraw(t.lv, func() {
					t.lv.Hwnd().SendMessage(co.LVM_SETITEMCOUNT, win.WPARAM(total), 0)
					restoreListHOrigin(t.lv, hOrigin)
					restoreScrollRatio(t.lv, oldTop, oldTotal, total)
				})
				t.app.setStatus("就绪")
			}
		})
	}()
}

func restoreScrollRatio(lv *ui.ListView, oldTop, oldTotal, newTotal int) {
	if lv == nil || lv.Hwnd() == 0 || oldTotal <= 1 || newTotal <= 1 || oldTop <= 0 {
		return
	}
	ratio := float64(oldTop) / float64(oldTotal-1)
	if ratio > 1 {
		ratio = 1
	}
	target := int(ratio * float64(newTotal-1))
	if target < 0 {
		target = 0
	}
	lv.Hwnd().SendMessage(co.LVM_ENSUREVISIBLE, win.WPARAM(target), 0)
}

func (t *sharedVirtualTable[T]) ensureBlock(block int) {
	if block < 0 {
		return
	}
	t.mu.Lock()
	if _, ok := t.cache[block]; ok || t.loading[block] {
		t.mu.Unlock()
		return
	}
	t.loading[block] = true
	gen, expr, sortField, desc, snapshot := t.gen, t.expr, t.sortField, t.desc, t.snapshot
	t.mu.Unlock()

	go func() {
		rows, err := t.pageFn(expr, virtualBlockSize, block*virtualBlockSize, sortField, desc, snapshot)
		t.mu.Lock()
		if t.gen != gen {
			t.mu.Unlock()
			return
		}
		delete(t.loading, block)
		if err == nil {
			if _, ok := t.cache[block]; !ok {
				t.cache[block] = rows
				t.order = append(t.order, block)
				for len(t.order) > virtualCacheLimit {
					old := t.order[0]
					t.order = t.order[1:]
					delete(t.cache, old)
				}
			}
		}
		t.mu.Unlock()
		if err == nil {
			t.app.wnd.UiThread(func() {
				if t.lv.Hwnd() != 0 {
					first := block * virtualBlockSize
					last := first + virtualBlockSize - 1
					if total := t.totalCount(); last >= total {
						last = total - 1
					}
					if last >= first {
						t.lv.Hwnd().SendMessage(co.LVM_REDRAWITEMS,
							win.WPARAM(first), win.LPARAM(last))
					}
					t.lv.Hwnd().RedrawWindow(nil, 0,
						co.RDW_INVALIDATE|co.RDW_UPDATENOW|co.RDW_ALLCHILDREN)
				}
			})
		} else {
			appPrintf("加载%s数据块 %d 失败：%v", t.kind, block, err)
		}
	}()
}

func (t *sharedVirtualTable[T]) row(index int) (T, bool) {
	var zero T
	if index < 0 {
		return zero, false
	}
	block := index / virtualBlockSize
	t.mu.Lock()
	defer t.mu.Unlock()
	rows, ok := t.cache[block]
	if !ok {
		return zero, false
	}
	off := index % virtualBlockSize
	if off < 0 || off >= len(rows) {
		return zero, false
	}
	return rows[off], true
}

func (t *sharedVirtualTable[T]) topIndex() int {
	ret, _ := t.lv.Hwnd().SendMessage(co.LVM_GETTOPINDEX, 0, 0)
	return int(ret)
}

func (t *sharedVirtualTable[T]) currentExpr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.expr
}

func (t *sharedVirtualTable[T]) currentSort() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sortField
}

func (t *sharedVirtualTable[T]) currentDesc() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.desc
}

func (t *sharedVirtualTable[T]) totalCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

func (t *sharedVirtualTable[T]) isCurrent(gen int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen == gen
}

func (t *sharedVirtualTable[T]) isDirty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dirty
}
