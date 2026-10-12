package httpclient

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

// NOTE: 该文件会被 C2 profile 模板引擎渲染,文件里不能出现 Go 复合字面量
// 产生的双花括号(会被当成模板 action)。因此下面用命名变量代替
// 匿名结构体切片的写法。

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestJarReplacesSameNameAndHonorsDeletion 回归测试:旧 Jar 只 append、
// 从不删除,同一会话的历史 cookie 会无限累积并在每个请求里重复发送,
// 造成服务端会话匹配错乱(404 / 202+Max-Age=0 循环)。
func TestJarReplacesSameNameAndHonorsDeletion(t *testing.T) {
	jar := cookieJar()
	u, _ := url.Parse("https://c2.example/")

	first := &http.Cookie{Name: "JSESSIONID", Value: "first"}
	second := &http.Cookie{Name: "JSESSIONID", Value: "second"}
	jar.SetCookies(u, []*http.Cookie{first})
	jar.SetCookies(u, []*http.Cookie{second})

	got := jar.Cookies(u)
	if len(got) != 1 || got[0].Value != "second" {
		t.Fatalf("expected a single cookie with the latest value, got %#v", got)
	}

	deleted := &http.Cookie{Name: "JSESSIONID", Value: "", MaxAge: -1}
	jar.SetCookies(u, []*http.Cookie{deleted})
	if got := jar.Cookies(u); len(got) != 0 {
		t.Fatalf("expected Max-Age<0 to delete the cookie, got %#v", got)
	}

	live := &http.Cookie{Name: "authToken", Value: "x"}
	expired := &http.Cookie{Name: "authToken", Value: "y", Expires: time.Now().Add(-time.Minute)}
	jar.SetCookies(u, []*http.Cookie{live})
	jar.SetCookies(u, []*http.Cookie{expired})
	if got := jar.Cookies(u); len(got) != 0 {
		t.Fatalf("expected an expired cookie to be deleted, got %#v", got)
	}
}
