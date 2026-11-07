//go:build windows

package main

import (
	"bytes"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// decodeWinText 统一解码控制台程序的输出：wevtutil 可能是 GBK，
// Sysmon 的部分输出是 UTF-16LE，XML 查询结果则保持 UTF-8。
func decodeWinText(b []byte) string {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	if s, ok := decodeUTF16Text(b); ok {
		return s
	}
	if utf8.Valid(b) {
		return string(b)
	}
	if s, err := simplifiedchinese.GBK.NewDecoder().String(string(b)); err == nil {
		return s
	}
	return string(b)
}

// toCRLF 让多行 EDIT 控件正确换行（Windows 的 EDIT 只认 CRLF）。
func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func decodeUTF16Text(b []byte) (string, bool) {
	le := false
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		b, le = b[2:], true
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		b = b[2:]
	default:
		if len(b) < 4 || len(b)%2 != 0 {
			return "", false
		}
		zeros := 0
		for i := 1; i < len(b); i += 2 {
			if b[i] == 0 {
				zeros++
			}
		}
		if zeros*4 < len(b)/2 {
			return "", false
		}
		le = true
	}
	if len(b) < 2 {
		return "", true
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		if le {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	return string(utf16.Decode(u)), true
}
