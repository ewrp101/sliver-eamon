package c2profiles

/*
	Sliver Implant Framework
	Copyright (C) 2026  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"strings"
	"testing"
)

func TestTruncateForDisplayShort(t *testing.T) {
	if got := truncateForDisplay("abc"); got != "abc" {
		t.Fatalf("expected unchanged short string, got %q", got)
	}
}

// TestTruncateForDisplayMultibyteDoesNotPanic 回归测试:
// 字节数 > 50 但 rune 数 <= 50 的多字节字符串此前会触发
// "slice bounds out of range" panic(查看 profile 时客户端直接退出)。
func TestTruncateForDisplayMultibyteDoesNotPanic(t *testing.T) {
	s := strings.Repeat("中", 20) // 60 bytes, 20 runes
	if got := truncateForDisplay(s); got != s {
		t.Fatalf("expected unchanged (<50 runes), got %q", got)
	}
}

func TestTruncateForDisplayLongASCII(t *testing.T) {
	got := truncateForDisplay(strings.Repeat("a", 60))
	if got != strings.Repeat("a", 50)+"..." {
		t.Fatalf("unexpected truncation: %q", got)
	}
}

func TestTruncateForDisplayLongMultibyte(t *testing.T) {
	got := truncateForDisplay(strings.Repeat("中", 60)) // 180 bytes, 60 runes
	if got != strings.Repeat("中", 50)+"..." {
		t.Fatalf("unexpected truncation: %q", got)
	}
}
