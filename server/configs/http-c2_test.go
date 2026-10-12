package configs

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"errors"
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func TestCoerceHeaderProbability(t *testing.T) {
	headers := []*clientpb.HTTPC2Header{
		{Name: "no-probability", Value: "a"},
		{Name: "explicit-probability", Value: "b", Probability: 25},
		{Name: "full-probability", Value: "c", Probability: 100},
	}

	coerceHeaderProbability(headers)

	for _, header := range headers {
		if header.Probability == 0 {
			t.Errorf("expected header %q to have a non-zero probability, got 0", header.Name)
		}
	}
	if headers[0].Probability != 100 {
		t.Errorf("expected missing probability to default to 100, got %d", headers[0].Probability)
	}
	if headers[1].Probability != 25 {
		t.Errorf("expected explicit probability 25 to be preserved, got %d", headers[1].Probability)
	}
	if headers[2].Probability != 100 {
		t.Errorf("expected explicit probability 100 to be preserved, got %d", headers[2].Probability)
	}
}

func TestCheckHTTPC2ConfigDefaultsHeaderProbability(t *testing.T) {
	config := &clientpb.HTTPC2Config{
		ServerConfig: &clientpb.HTTPC2ServerConfig{
			Headers: []*clientpb.HTTPC2Header{
				{Name: "server-header", Value: "a"},
			},
			Cookies: []*clientpb.HTTPC2Cookie{
				{Name: "jsessionid"},
			},
		},
		ImplantConfig: &clientpb.HTTPC2ImplantConfig{
			Headers: []*clientpb.HTTPC2Header{
				{Name: "implant-header", Value: "b"},
				{Name: "complete-header", Value: "c", Probability: 50},
			},
			Extensions: []string{"js", "php"},
			PathSegments: []*clientpb.HTTPC2PathSegment{
				{IsFile: true, Value: "index"},
			},
		},
	}

	err := checkHTTPC2Config(config)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if config.ServerConfig.Headers[0].Probability != 100 {
		t.Errorf("expected server header probability to default to 100, got %d", config.ServerConfig.Headers[0].Probability)
	}
	if config.ImplantConfig.Headers[0].Probability != 100 {
		t.Errorf("expected implant header probability to default to 100, got %d", config.ImplantConfig.Headers[0].Probability)
	}
	if config.ImplantConfig.Headers[1].Probability != 50 {
		t.Errorf("expected explicit probability 50 to be preserved, got %d", config.ImplantConfig.Headers[1].Probability)
	}
}

// TestParseAlpnTokensAllowsHTTP11 回归测试:tls_alpn 允许 "http/1.1"(含 '/'),
// 这是 uTLS 路径下与 Sliver 监听器协商所必需的值。
func TestParseAlpnTokensAllowsHTTP11(t *testing.T) {
	tokens, err := parseAlpnTokens("h2, http/1.1")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(tokens) != 2 || tokens[0] != "h2" || tokens[1] != "http/1.1" {
		t.Fatalf("unexpected tokens: %#v", tokens)
	}
}

func TestParseAlpnTokensRejectsInvalidToken(t *testing.T) {
	if _, err := parseAlpnTokens("h2;rm"); !errors.Is(err, ErrTLSAlpnInvalid) {
		t.Fatalf("expected ErrTLSAlpnInvalid, got %v", err)
	}
}

func TestParseAlpnTokensEmpty(t *testing.T) {
	tokens, err := parseAlpnTokens("   ")
	if err != nil || tokens != nil {
		t.Fatalf("expected nil tokens/nil error, got %#v / %v", tokens, err)
	}
}

func TestCheckTLSClientHelloConfigPresetWithHTTP11Alpn(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:       true,
		TlsClientHelloID: "chrome_133",
		TlsAlpnOverride:  "http/1.1",
	}
	if err := checkTLSClientHelloConfig(config); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCheckTLSClientHelloConfigRandomizedAlpnRejected(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:       true,
		TlsClientHelloID: "randomized",
		TlsAlpnOverride:  "http/1.1",
	}
	if err := checkTLSClientHelloConfig(config); !errors.Is(err, ErrTLSAlpnRandomized) {
		t.Fatalf("expected ErrTLSAlpnRandomized, got %v", err)
	}
}

func TestCheckTLSClientHelloConfigUnknownPreset(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:       true,
		TlsClientHelloID: "chrome_999",
	}
	if err := checkTLSClientHelloConfig(config); err == nil {
		t.Fatal("expected an error for an unknown preset")
	}
}

func TestCheckTLSClientHelloConfigDisabledClearsTLSFields(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:        false,
		TlsClientHelloID:  "chrome_133",
		TlsCustomSpecJSON: `{"a":1}`,
		TlsAlpnOverride:   "http/1.1",
		HttpHeaderOrder:   "Host,User-Agent",
	}
	if err := checkTLSClientHelloConfig(config); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if config.TlsClientHelloID != "" || config.TlsCustomSpecJSON != "" || config.TlsAlpnOverride != "" {
		t.Fatalf("expected TLS fields to be cleared, got %#v", config)
	}
	// HTTP 头层指纹独立于 TLS,必须保留
	if config.HttpHeaderOrder != "Host,User-Agent" {
		t.Fatalf("expected HTTP header order preserved, got %q", config.HttpHeaderOrder)
	}
}

func TestCheckTLSClientHelloConfigInvalidHeaderOrder(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:      false,
		HttpHeaderOrder: "Host,Bad Header",
	}
	if err := checkTLSClientHelloConfig(config); !errors.Is(err, ErrHTTPHeaderOrderInvalid) {
		t.Fatalf("expected ErrHTTPHeaderOrderInvalid, got %v", err)
	}
}

func TestCheckTLSClientHelloConfigIllegalBacktick(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		TlsEnabled:        true,
		TlsCustomSpecJSON: "`",
	}
	if err := checkTLSClientHelloConfig(config); !errors.Is(err, ErrTLSIllegalCharacters) {
		t.Fatalf("expected ErrTLSIllegalCharacters, got %v", err)
	}
}

// TestCheckImplantConfigRequiresFileSegment 回归测试:没有文件段的 profile 会
// 让 implant 的 randomPath() 对空切片取 Intn 而 panic,必须在保存时拒绝。
func TestCheckImplantConfigRequiresFileSegment(t *testing.T) {
	config := &clientpb.HTTPC2ImplantConfig{
		Extensions:   []string{"js"},
		PathSegments: []*clientpb.HTTPC2PathSegment{{IsFile: false, Value: "api"}},
	}
	if err := checkImplantConfig(config); !errors.Is(err, ErrMissingFiles) {
		t.Fatalf("expected ErrMissingFiles for paths-only profile, got %v", err)
	}

	config.PathSegments = append(config.PathSegments, &clientpb.HTTPC2PathSegment{IsFile: true, Value: "index"})
	if err := checkImplantConfig(config); err != nil {
		t.Fatalf("expected profile with a file segment to pass, got %v", err)
	}
}
