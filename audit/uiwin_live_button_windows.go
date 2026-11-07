//go:build windows

package main

import (
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

func makeLiveTransportIcon(pause bool, size int) (win.HICON, error) {
	if size < 12 {
		size = 12
	}
	sz := win.SIZE{Cx: int32(size), Cy: int32(size)}
	screen, err := win.HWND(0).GetDC()
	if err != nil {
		return 0, err
	}
	defer win.HWND(0).ReleaseDC(screen)

	colorBmp, err := screen.CreateCompatibleBitmap(size, size)
	if err != nil {
		return 0, err
	}
	defer colorBmp.DeleteObject()
	colorDC, err := screen.CreateCompatibleDC()
	if err != nil {
		return 0, err
	}
	defer colorDC.DeleteDC()

	stride := ((size + 15) / 16) * 2
	maskBits := make([]byte, stride*size)
	for i := range maskBits {
		maskBits[i] = 0xFF
	}
	maskBmp, err := win.CreateBitmap(sz, 1, 1, maskBits)
	if err != nil {
		return 0, err
	}
	defer maskBmp.DeleteObject()
	maskDC, err := screen.CreateCompatibleDC()
	if err != nil {
		return 0, err
	}
	defer maskDC.DeleteDC()

	colorOld, _ := colorDC.SelectObjectBmp(colorBmp)
	maskOld, _ := maskDC.SelectObjectBmp(maskBmp)
	white, _ := win.GetStockObject(co.STOCK_WHITE_BRUSH)
	rc := win.RECT{Right: int32(size), Bottom: int32(size)}
	_ = colorDC.FillRect(&rc, win.HBRUSH(white))
	drawLiveIconShape(colorDC, size, pause, win.GetSysColor(co.COLOR_BTNTEXT))
	drawLiveIconShape(maskDC, size, pause, win.RGB(0, 0, 0))
	if colorOld != 0 {
		_, _ = colorDC.SelectObjectBmp(colorOld)
	}
	if maskOld != 0 {
		_, _ = maskDC.SelectObjectBmp(maskOld)
	}

	hIcon, err := win.CreateIconIndirect(&win.ICONINFO{
		FIcon:    win.BOOL(1),
		HbmMask:  maskBmp,
		HbmColor: colorBmp,
	})
	if err != nil {
		return 0, err
	}
	return hIcon, nil
}

func drawLiveIconShape(hdc win.HDC, size int, pause bool, color win.COLORREF) {
	h, _, _ := procCreateSolidBrush.Call(uintptr(color))
	if h == 0 {
		return
	}
	brush := win.HBRUSH(h)
	defer brush.DeleteObject()
	oldBrush, _ := hdc.SelectObjectBrush(brush)
	nullPen, _ := win.GetStockObject(co.STOCK_NULL_PEN)
	oldPen, _ := hdc.SelectObjectPen(win.HPEN(nullPen))
	defer hdc.SelectObjectBrush(oldBrush)
	defer hdc.SelectObjectPen(oldPen)

	if pause {
		barW := int32(size / 5)
		gap := int32(size / 5)
		barH := int32(size * 3 / 5)
		top := (int32(size) - barH) / 2
		left := (int32(size) - (barW*2 + gap)) / 2
		_ = hdc.Rectangle(win.RECT{Left: left, Top: top, Right: left + barW, Bottom: top + barH})
		left += barW + gap
		_ = hdc.Rectangle(win.RECT{Left: left, Top: top, Right: left + barW, Bottom: top + barH})
		return
	}

	left := int32(size * 3 / 10)
	right := int32(size * 7 / 10)
	top := int32(size * 2 / 10)
	bottom := int32(size * 8 / 10)
	_ = hdc.Polygon([]win.POINT{
		{X: left, Y: top},
		{X: right, Y: int32(size) / 2},
		{X: left, Y: bottom},
	})
}
