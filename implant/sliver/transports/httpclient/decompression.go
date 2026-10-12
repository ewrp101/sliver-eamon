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

// {{if .Config.IncludeHTTP}}

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decompressTransport - 按 Content-Encoding 解压响应体的 RoundTripper。
//
// 背景:profile 常常显式设置 Accept-Encoding(为了 JA4H 像浏览器),
// 而 Go 的 http.Transport 只在“自己注入 Accept-Encoding: gzip”时才会自动解压。
// 一旦上游/CDN(Cloudflare 等)对 C2 响应做 gzip/br/zstd 压缩,植入体就会拿到
// 压缩字节并解析失败。这里统一在 RoundTrip 出口解压,保证载荷始终是明文。
type decompressTransport struct {
	base http.RoundTripper
}

func (t *decompressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding == "" || encoding == "identity" {
		return resp, nil
	}

	var reader io.Reader
	closers := []io.Closer{}
	switch encoding {
	case "gzip", "x-gzip":
		zr, zerr := gzip.NewReader(resp.Body)
		if zerr != nil {
			return nil, zerr
		}
		reader = zr
		closers = append(closers, zr)
	case "deflate":
		// RFC 2616 的 deflate 既可能是 zlib 包装,也可能是裸 flate。
		zr, zerr := zlib.NewReader(resp.Body)
		if zerr != nil {
			reader = flate.NewReader(resp.Body)
		} else {
			reader = zr
			closers = append(closers, zr)
		}
	case "br":
		reader = brotli.NewReader(resp.Body)
	case "zstd":
		dec, zerr := zstd.NewReader(resp.Body)
		if zerr != nil {
			return nil, zerr
		}
		rc := dec.IOReadCloser()
		reader = rc
		closers = append(closers, rc)
	default:
		// 未知/多重编码:不处理,交由上层(保持原状)
		return resp, nil
	}

	resp.Body = &decompressedBody{Reader: reader, closers: append(closers, resp.Body)}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return resp, nil
}

type decompressedBody struct {
	io.Reader
	closers []io.Closer
}

func (b *decompressedBody) Close() error {
	var firstErr error
	for _, closer := range b.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// {{end}} -IncludeHTTP
