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
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/server/log"
	utls "github.com/refraction-networking/utls"
)

const (
	DefaultChromeBaseVer = 106
	DefaultMacOSVer      = "10_15_7"
)

// CheckHTTPC2ConfigErrors - Get the current HTTP C2 config
func CheckHTTPC2ConfigErrors(config *clientpb.HTTPC2Config) error {
	err := checkHTTPC2Config(config)
	if err != nil {
		httpC2ConfigLog.Errorf("Invalid http c2 config: %s", err)
		return err
	}
	return nil
}

var (
	ErrMissingCookies             = errors.New("server config must specify at least one cookie")
	ErrMissingExtensions          = errors.New("implant config must specify at least one file extension")
	ErrMissingFiles               = errors.New("implant config must specify at least one files value")
	ErrMissingPaths               = errors.New("implant config must specify at least one paths value")
	ErrDuplicateC2ProfileName     = errors.New("C2 Profile name is already in use")
	ErrMissingC2ProfileName       = errors.New("C2 Profile name is required")
	ErrC2ProfileNotFound          = errors.New("C2 Profile does not exist")
	ErrUserAgentIllegalCharacters = errors.New("user agent cannot contain the ` character")

	ErrTLSClientHelloMissing = errors.New("TLS fingerprint enabled but neither a preset nor a custom ClientHelloSpec is set")
	ErrTLSIllegalCharacters  = errors.New("TLS ClientHello settings cannot contain the ` character")
	ErrTLSCustomSpecInvalid  = errors.New("TLS custom ClientHelloSpec JSON failed to parse")

	ErrTLSAlpnInvalid         = errors.New("TLS ALPN override contains an invalid RFC 7301 protocol token")
	ErrTLSAlpnRandomized      = errors.New("TLS ALPN override cannot be combined with a randomized preset (the spec is generated at runtime)")
	ErrHTTPHeaderOrderInvalid = errors.New("HTTP header order/suppress list contains an invalid header name")

	fileNameExp = regexp.MustCompile(`[^a-zA-Z0-9\\._-]+`)

	// RFC 7301 ALPN protocol name / RFC 7230 header field-name(token):
	// 可见 ASCII,排除分隔符与空格
	tokenExp = regexp.MustCompile(`^[a-zA-Z0-9!#$%&'*+\-.^_|~]+$`)

	// RFC 7301 ALPN 协议名允许使用 "/"(如 "http/1.1"),而 RFC 7230 的
	// header token 不允许。两者不能共用同一个正则,否则 http/1.1 会被误拒。
	alpnTokenExp = regexp.MustCompile(`^[a-zA-Z0-9!#$%&'*+\-.^_|~/]+$`)
)

// randomizedPresets - 运行时生成 spec 的预设,无法物化(J4H/ALPN 覆盖不适用)
var randomizedPresets = map[string]bool{
	"randomized":         true,
	"randomized_alpn":    true,
	"randomized_no_alpn": true,
}

// TLSClientHelloPresets - profile 规范化预设名 -> uTLS ClientHelloID。
// 必须与 implant/sliver/transports/httpclient/utlsclient.go 中的同名表保持一致;
// 服务端以此表为白名单校验,implant 侧以此表在构建期解析预设。
// 名单来源:utls v1.8.2 u_common.go 预设 var 块(HelloChrome_Auto=133, HelloFirefox_Auto=120)。
var TLSClientHelloPresets = map[string]utls.ClientHelloID{
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
	// 106 起扩展顺序带 shuffle;PSK/PQ 变体在 uTLS 中仍为 beta,谨慎使用
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
	"firefox_auto":                utls.HelloFirefox_Auto,
	"firefox_55":                  utls.HelloFirefox_55,
	"firefox_56":                  utls.HelloFirefox_56,
	"firefox_63":                  utls.HelloFirefox_63,
	"firefox_65":                  utls.HelloFirefox_65,
	"firefox_99":                  utls.HelloFirefox_99,
	"firefox_102":                 utls.HelloFirefox_102,
	"firefox_105":                 utls.HelloFirefox_105,
	"firefox_120":                 utls.HelloFirefox_120,
	"safari_auto":                 utls.HelloSafari_Auto,
	"safari_16_0":                 utls.HelloSafari_16_0,
	"ios_auto":                    utls.HelloIOS_Auto,
	"ios_11_1":                    utls.HelloIOS_11_1,
	"ios_12_1":                    utls.HelloIOS_12_1,
	"ios_13":                      utls.HelloIOS_13,
	"ios_14":                      utls.HelloIOS_14,
	"android_11_okhttp":           utls.HelloAndroid_11_OkHttp,
	"edge_auto":                   utls.HelloEdge_Auto,
	"edge_85":                     utls.HelloEdge_85,
	"edge_106":                    utls.HelloEdge_106,
	"360_auto":                    utls.Hello360_Auto,
	"360_7_5":                     utls.Hello360_7_5,
	"360_11_0":                    utls.Hello360_11_0,
	"qq_auto":                     utls.HelloQQ_Auto,
	"qq_11_1":                     utls.HelloQQ_11_1,
	"randomized":                  utls.HelloRandomized,
	"randomized_alpn":             utls.HelloRandomizedALPN,
	"randomized_no_alpn":          utls.HelloRandomizedNoALPN,
}

// TLSClientHelloPresetNames - 供错误提示使用
func TLSClientHelloPresetNames() []string {
	names := make([]string, 0, len(TLSClientHelloPresets))
	for name := range TLSClientHelloPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// checkHTTPC2Config - Validate the HTTP C2 config, coerces common mistakes
func checkHTTPC2Config(config *clientpb.HTTPC2Config) error {
	coerceHeaderProbability(config.ServerConfig.Headers)
	coerceHeaderProbability(config.ImplantConfig.Headers)

	err := checkServerConfig(config.ServerConfig)
	if err != nil {
		return err
	}
	return checkImplantConfig(config.ImplantConfig)
}

// coerceHeaderProbability - Header probability defaults to the protobuf zero
// value (0) when omitted from the config, which means the header is never sent
// by the implant. Default to 100 so the header is always applied.
func coerceHeaderProbability(headers []*clientpb.HTTPC2Header) {
	for _, header := range headers {
		if header.Probability == 0 {
			httpC2ConfigLog.Warnf("Header %q is missing a probability, defaulting to 100", header.Name)
			header.Probability = 100
		}
	}
}

func coerceFileExt(value string) string {
	value = fileNameExp.ReplaceAllString(value, "")
	for strings.HasPrefix(value, ".") {
		value = strings.TrimPrefix(value, ".")
	}
	return value
}

func checkServerConfig(config *clientpb.HTTPC2ServerConfig) error {
	if len(config.Cookies) < 1 {
		return ErrMissingCookies
	}
	return nil
}

func checkImplantConfig(config *clientpb.HTTPC2ImplantConfig) error {

	// min and max used during http c2 config generation
	if config.MinFileGen < 1 {
		config.MinFileGen = 1
	}
	if config.MaxFileGen < config.MinFileGen {
		config.MaxFileGen = config.MinFileGen
	}
	if config.MinPathGen < 0 {
		config.MinPathGen = 0
	}
	if config.MaxPathGen < config.MinPathGen {
		config.MaxPathGen = config.MinPathGen
	}

	// Path length used during implant operation
	if config.MinPathLength < 1 {
		config.MinPathLength = 1
	}
	if config.MaxPathLength < config.MinPathLength {
		config.MaxPathLength = config.MinPathLength
	}

	// File Extensions
	if len(config.Extensions) < 1 {
		return ErrMissingExtensions
	}

	// 至少需要一个文件段:implant 的 randomPath() 会执行
	// filenames[Intn(len(filenames))],文件段为空时会在运行时 panic。
	// path 段是可选的(见 randomPath)。
	fileSegmentCount := 0
	for _, segment := range config.PathSegments {
		if segment.IsFile {
			fileSegmentCount++
		}
	}
	if fileSegmentCount < 1 {
		return ErrMissingFiles
	}

	/*
		User agent

		Do not allow backticks in user agents because that breaks compilation of the
		implant.
	*/
	if strings.Contains(config.UserAgent, "`") {
		// Blank out the user agent so that a default one will be filled in later
		config.UserAgent = ""
		return ErrUserAgentIllegalCharacters
	}

	return checkTLSClientHelloConfig(config)
}

// checkTLSClientHelloConfig - 校验 uTLS ClientHello 指纹配置。
// TlsEnabled=false 时清空相关字段,保证旧 profile 与默认行为零变化。
func checkTLSClientHelloConfig(config *clientpb.HTTPC2ImplantConfig) error {
	if !config.TlsEnabled {
		config.TlsClientHelloID = ""
		config.TlsCustomSpecJSON = ""
		config.TlsAlpnOverride = ""
		// HTTP 头层指纹独立于 TLS 指纹,明文 HTTP 场景同样生效
		return checkHTTPHeaderFingerprint(config)
	}

	// 模板以反引号原始字符串渲染 spec,禁止反引号字符
	if strings.Contains(config.TlsCustomSpecJSON, "`") || strings.Contains(config.TlsClientHelloID, "`") ||
		strings.Contains(config.TlsAlpnOverride, "`") {
		return ErrTLSIllegalCharacters
	}

	alpnProtocols, err := parseAlpnTokens(config.TlsAlpnOverride)
	if err != nil {
		return err
	}

	if config.TlsCustomSpecJSON != "" {
		// Tier 2:直接用 vendored uTLS 库做全量结构校验,避免校验逻辑与库漂移
		spec := utls.ClientHelloSpec{}
		if err := spec.UnmarshalJSON([]byte(config.TlsCustomSpecJSON)); err != nil {
			return fmt.Errorf("%w: %s", ErrTLSCustomSpecInvalid, err)
		}
		if len(alpnProtocols) > 0 && !specHasALPN(&spec) {
			httpC2ConfigLog.Warnf("TLS ALPN override %q 已配置但自定义 spec 无 ALPN 扩展;"+
				"为避免改写扩展顺序(影响 JA3),该覆盖不会生效", config.TlsAlpnOverride)
		}
		// 仅在未显式覆盖 ALPN 时告警
		if len(alpnProtocols) == 0 && specHasH2(&spec) {
			httpC2ConfigLog.Warnf("Custom ClientHelloSpec advertises h2 via ALPN: 直连 Sliver HTTPS 监听器安全(仅应答 http/1.1)," +
				"但若 C2 前置了会协商 HTTP/2 的 CDN/反代,连接将协议错乱失败;可用 TlsAlpnOverride=http/1.1 规避")
		}
	} else {
		if config.TlsClientHelloID == "" {
			return ErrTLSClientHelloMissing
		}
		if _, ok := TLSClientHelloPresets[config.TlsClientHelloID]; !ok {
			return fmt.Errorf("unknown TLS ClientHello preset %q (valid: %s)",
				config.TlsClientHelloID, strings.Join(TLSClientHelloPresetNames(), ", "))
		}
		// randomized 系列在运行时生成 spec,无法物化以重写 ALPN
		if len(alpnProtocols) > 0 && randomizedPresets[config.TlsClientHelloID] {
			return ErrTLSAlpnRandomized
		}
		if len(alpnProtocols) == 0 && presetAdvertisesH2(config.TlsClientHelloID) {
			httpC2ConfigLog.Warnf("Preset %q 的 ALPN 含 h2: 直连 Sliver 监听器安全;前置会协商 HTTP/2 的 CDN/反代时连接会失败"+
				"(可用 TlsAlpnOverride=http/1.1 规避)", config.TlsClientHelloID)
		}
	}
	return checkHTTPHeaderFingerprint(config)
}

// presetAdvertisesH2 - 主流浏览器预设的 ALPN 均含 h2(uTLS u_parrots.go 核实)
func presetAdvertisesH2(name string) bool {
	return strings.HasPrefix(name, "chrome_") ||
		strings.HasPrefix(name, "firefox_") ||
		strings.HasPrefix(name, "safari_") ||
		strings.HasPrefix(name, "edge_") ||
		strings.HasPrefix(name, "ios_") ||
		strings.HasPrefix(name, "android_")
}

// parseAlpnTokens - 校验并返回 ALPN token 列表;空配置返回 nil
func parseAlpnTokens(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	tokens := []string{}
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if !alpnTokenExp.MatchString(token) {
			return nil, fmt.Errorf("%w: %q", ErrTLSAlpnInvalid, token)
		}
		tokens = append(tokens, token)
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("%w: empty list", ErrTLSAlpnInvalid)
	}
	// uTLS 路径下 implant 只会说 HTTP/1.1;若覆盖后不含 http/1.1 将无法与监听器协商
	hasHTTP11 := false
	for _, token := range tokens {
		if token == "http/1.1" {
			hasHTTP11 = true
		}
	}
	if !hasHTTP11 {
		httpC2ConfigLog.Warnf("TlsAlpnOverride %q 不含 http/1.1: uTLS 驱动的 implant 仅支持 HTTP/1.1,握手可能协商失败",
			value)
	}
	return tokens, nil
}

// checkHTTPHeaderFingerprint - 校验 HTTP 头块指纹配置
func checkHTTPHeaderFingerprint(config *clientpb.HTTPC2ImplantConfig) error {
	for _, list := range []string{config.HttpHeaderOrder, config.HttpSuppressHeaders} {
		for _, name := range strings.Split(list, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !tokenExp.MatchString(name) {
				return fmt.Errorf("%w: %q", ErrHTTPHeaderOrderInvalid, name)
			}
		}
	}
	return nil
}

// specHasH2 - 检查自定义 spec 的 ALPN 扩展是否包含 h2
func specHasH2(spec *utls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			for _, proto := range alpn.AlpnProtocols {
				if proto == "h2" {
					return true
				}
			}
		}
	}
	return false
}

// specHasALPN - 自定义 spec 是否含 ALPN 扩展(决定 ALPN 覆盖能否生效)
func specHasALPN(spec *utls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			return true
		}
	}
	return false
}

func GenerateDefaultHTTPC2Config() *clientpb.HTTPC2Config {

	// Implant Config
	httpC2UrlParameters := []*clientpb.HTTPC2URLParameter{}
	httpC2Headers := []*clientpb.HTTPC2Header{}
	pathSegments := GenerateHTTPC2DefaultPathSegment()

	implantConfig := clientpb.HTTPC2ImplantConfig{
		UserAgent:          "",
		ChromeBaseVersion:  DefaultChromeBaseVer,
		MacOSVersion:       DefaultMacOSVer,
		NonceQueryArgChars: "abcdefghijklmnopqrstuvwxyz",
		NonceQueryLength:   1,
		NonceMode:          "UrlParam", // Url or UrlParam
		ExtraURLParameters: httpC2UrlParameters,
		Headers:            httpC2Headers,
		MaxFileGen:         4,
		MinFileGen:         2,
		MaxPathGen:         4,
		MinPathGen:         2,
		MaxPathLength:      4,
		MinPathLength:      2,
		Extensions: []string{
			"js", "", "php",
		},
		PathSegments: pathSegments,
	}

	// Server Config
	serverHeaders := []*clientpb.HTTPC2Header{
		{
			Method:      "GET",
			Name:        "Cache-Control",
			Value:       "no-store, no-cache, must-revalidate",
			Probability: 100,
		},
	}
	cookies := GenerateDefaultHTTPC2Cookies()
	serverConfig := clientpb.HTTPC2ServerConfig{
		RandomVersionHeaders: false,
		Headers:              serverHeaders,
		Cookies:              cookies,
	}

	// HTTPC2Config

	defaultConfig := clientpb.HTTPC2Config{
		ServerConfig:  &serverConfig,
		ImplantConfig: &implantConfig,
		Name:          "default",
	}

	return &defaultConfig
}

func GenerateDefaultHTTPC2Cookies() []*clientpb.HTTPC2Cookie {
	cookies := []*clientpb.HTTPC2Cookie{}
	for _, cookie := range Cookies {
		cookies = append(cookies, &clientpb.HTTPC2Cookie{
			Name: cookie,
		})
	}
	return cookies
}

func GenerateHTTPC2DefaultPathSegment() []*clientpb.HTTPC2PathSegment {
	pathSegments := []*clientpb.HTTPC2PathSegment{}

	/*
		IsFile      bool
		Value       string
	*/

	// files
	for _, file := range Files {
		pathSegments = append(pathSegments, &clientpb.HTTPC2PathSegment{
			IsFile: true,
			Value:  file,
		})
	}

	for _, path := range Paths {
		pathSegments = append(pathSegments, &clientpb.HTTPC2PathSegment{
			IsFile: false,
			Value:  path,
		})
	}

	return pathSegments
}

var (
	httpC2ConfigLog = log.NamedLogger("config", "http-c2")

	// Pro-tip: You can use ChatGPT to generate this stuff for you!
	Cookies = []string{
		"JSESSIONID",
		"rememberMe",
		"authToken",
		"userId",
		"userName",
		"language",
		"theme",
		"locale",
		"currency",
		"lastVisited",
		"loggedIn",
		"userRole",
		"cartId",
		"accessToken",
		"refreshToken",
		"consent",
		"notificationPreference",
		"userSettings",
		"sessionTimeout",
		"error",
		"errorMessage",
		"successMessage",
		"infoMessage",
		"warningMessage",
		"errorMessageKey",
		"successMessageKey",
		"infoMessageKey",
		"warningMessageKey",
		"sessionID",
		"userID",
		"username",
		"authToken",
		"rememberMe",
		"language",
		"theme",
		"locale",
		"currency",
		"lastVisit",
		"loggedIn",
		"userRole",
		"cartID",
		"accessToken",
		"refreshToken",
		"consent",
		"notificationPref",
		"userSettings",
		"sessionTimeout",
		"visitedPages",
		"favoriteItems",
		"searchHistory",
		"basketID",
		"promoCode",
		"campaignID",
		"referrer",
		"source",
		"utmCampaign",
		"utmSource",
		"utmMedium",
		"utmContent",
		"utmTerm",
		"deviceType",
		"OSVersion",
		"browser",
		"screenResolution",
		"timezone",
		"firstVisit",
		"feedbackGiven",
		"surveyID",
		"errorAlerts",
		"successAlerts",
		"infoAlerts",
		"warningAlerts",
		"darkMode",
		"emailSubscription",
		"privacyConsent",
		"PHPSESSID",
		"SID",
		"SSID",
		"APISID",
		"csrf-state",
		"AWSALBCORS",
	}
	Files = []string{
		"bootstrap",
		"bootstrap.min",
		"jquery.min",
		"jquery",
		"route",
		"app",
		"app.min",
		"array",
		"backbone",
		"script",
		"email",
		"main",
		"index",
		"utils",
		"jquery.min",
		"bootstrap",
		"angular",
		"react",
		"vue",
		"lodash",
		"moment",
		"axios",
		"underscore",
		"d3",
		"chart",
		"map",
		"validation",
		"animation",
		"slider",
		"modal",
		"form",
		"ajax",
		"cookie",
		"dom",
		"events",
		"navigation",
		"menu",
		"dropdown",
		"carousel",
		"scroll",
		"pagination",
		"tabs",
		"accordion",
		"tooltip",
		"popover",
		"alert",
		"notification",
		"progress",
		"loader",
		"countdown",
		"lazyload",
		"parallax",
		"video",
		"audio",
		"slideshow",
		"gallery",
		"lightbox",
		"share",
		"social",
		"analytics",
		"tracking",
		"search",
		"autocomplete",
		"filter",
		"sort",
		"table",
		"chart",
		"graph",
		"calendar",
		"datepicker",
		"timepicker",
		"dropdown",
		"multi-select",
		"form-validation",
		"tooltip",
		"popover",
		"modal",
		"sidebar",
		"drawer",
		"sticky",
		"scrollspy",
		"smoothscroll",
		"anchor",
		"slideshow",
		"testimonial",
		"newsletter",
		"login",
		"registration",
		"cart",
		"checkout",
		"payment",
		"validation",
		"maps",
		"geolocation",
		"geocoding",
		"canvas",
		"webgl",
		"particles",
		"barcode",
		"qr-code",
		"encryption",
		"decryption",
		"localization",
		"translation",
		"i18n",
		"routing",
		"router",
		"storage",
		"offline",
	}
	Paths = []string{
		"js",
		"umd",
		"assets",
		"bundle",
		"bundles",
		"scripts",
		"script",
		"javascripts",
		"javascript",
		"jscript",
		"js",
		"scripts",
		"assets",
		"src",
		"lib",
		"public",
		"static",
		"app",
		"www",
		"dist",
		"frontend",
		"client",
		"server",
		"resources",
		"jsfiles",
		"javascript",
		"jslib",
		"jslibraries",
		"jsdir",
		"jsfolder",
		"jsfilesdir",
		"jsfilesfolder",
		"scriptsdir",
		"assetsjs",
		"srcjs",
		"srcscripts",
		"libjs",
		"libscripts",
		"publicjs",
		"publicscripts",
		"staticjs",
		"staticscripts",
		"appjs",
		"appscripts",
		"distjs",
		"distscripts",
		"frontendjs",
		"frontendscripts",
		"clientjs",
		"clientscripts",
		"serverjs",
		"resourcesjs",
		"jsfilesjs",
		"jsfilesscripts",
		"javascriptjs",
		"jslibscripts",
		"assetsjs",
		"assetsjsscripts",
		"assetsjs",
		"assetsscripts",
		"srcjs",
		"srcjsscripts",
		"srcscripts",
		"srcscripts",
		"libjs",
		"libjsscripts",
	}
)
