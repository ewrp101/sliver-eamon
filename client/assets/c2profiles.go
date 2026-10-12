package assets

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

// HTTPC2Config - Parent config file struct for implant/server
type HTTPC2Config struct {
	ImplantConfig HTTPC2ImplantConfig `json:"implant_config"`
	ServerConfig  HTTPC2ServerConfig  `json:"server_config"`
}

// HTTPC2ServerConfig - Server configuration options
type HTTPC2ServerConfig struct {
	RandomVersionHeaders bool                   `json:"random_version_headers"`
	Headers              []NameValueProbability `json:"headers"`
	Cookies              []string               `json:"cookies"`
}

type NameValueProbability struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Probability int    `json:"probability"`
	Method      string `json:"method"`
}

// HTTPC2ImplantConfig - Implant configuration options
// Procedural C2
// ===============
// .txt = rsakey
// .css = start
// .php = session
//
//	.js = poll
//
// .png = stop
// .woff = sliver shellcode
type HTTPC2ImplantConfig struct {
	UserAgent         string `json:"user_agent"`
	ChromeBaseVersion int    `json:"chrome_base_version"`
	MacOSVersion      string `json:"macos_version"`

	NonceQueryArgChars string                 `json:"nonce_query_args"`
	URLParameters      []NameValueProbability `json:"url_parameters"`
	Headers            []NameValueProbability `json:"headers"`
	NonceQueryLength   int                    `json:"nonce_query_length"`
	NonceMode          string                 `json:"nonce_mode"`

	MaxFileGen    int `json:"max_files"`
	MinFileGen    int `json:"min_files"`
	MaxPathGen    int `json:"max_paths"`
	MinPathGen    int `json:"min_paths"`
	MaxPathLength int `json:"max_path_length"`
	MinPathLength int `json:"min_path_length"`

	Extensions []string `json:"extensions"`
	Files      []string `json:"files"`
	Paths      []string `json:"paths"`

	// [ TLS / ClientHello 指纹 (uTLS) ]
	// TLSEnabled 为总开关,关闭时 implant 使用原生 crypto/tls,行为与旧版本完全一致。
	TLSEnabled bool `json:"tls_enabled"`
	// TLSClientHelloID 为 Tier 1 预设名(如 "chrome_auto"/"chrome_133"/"firefox_auto"/
	// "safari_16_0"/"randomized"),设置 TLSCustomSpecJSON 时该项被忽略。
	TLSClientHelloID string `json:"tls_client_hello_id"`
	// TLSCustomSpecJSON 为 Tier 2 自定义 ClientHelloSpec(uTLS dicttls JSON 格式),
	// 非空时以 HelloCustom + ApplyPreset 方式生效,可逐字段控制 JA3/JA4。
	TLSCustomSpecJSON string `json:"tls_custom_spec_json"`
}
