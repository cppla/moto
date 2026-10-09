package http2

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	httpcommon "moto/internal/browserhttpcommon"

	"golang.org/x/net/http2/hpack"
)

var errChromeResponseHeaderListSize = errors.New("http2: response header list exceeds local acceptance limit")

const (
	chromeHeaderTableSize           = 65536
	chromeStreamWindow              = 6291456
	chromeConnectionWindowIncrement = 15663105
	chromeMaxHeaderListSize         = 262144
)

// The advertised SETTINGS and the actual receive windows/decoder capacity must
// agree. This changes receive credit, never the peer-controlled send window.
func applyChromeReceiveConfig(conf *http2Config) {
	conf.MaxDecoderHeaderTableSize = chromeHeaderTableSize
	conf.MaxUploadBufferPerStream = chromeStreamWindow
	conf.MaxUploadBufferPerConnection = chromeConnectionWindowIncrement
	conf.MaxReadFrameSize = 16384
}

func chromeInitialSettings() []Setting {
	return []Setting{
		{ID: SettingHeaderTableSize, Val: chromeHeaderTableSize},
		{ID: SettingEnablePush, Val: 0},
		{ID: SettingInitialWindowSize, Val: chromeStreamWindow},
		{ID: SettingMaxHeaderListSize, Val: chromeMaxHeaderListSize},
	}
}

// Enforce the caller's smaller application policy on raw decoded fields, before
// net/http removes, combines or moves any of them into Response.Trailer. The
// decoder itself accepts the capacity announced in SETTINGS. A rejection is
// stream-scoped and leaves the shared HPACK state and sibling streams usable.
func chromeResponseHeadersTooLarge(frame *MetaHeadersFrame, limit uint32) bool {
	if frame.Truncated {
		return true
	}
	if limit == 0 {
		return false
	}
	var size uint64
	for _, field := range frame.Fields {
		size += uint64(len(field.Name)) + uint64(len(field.Value)) + 32
		if size > uint64(limit) {
			return true
		}
	}
	return false
}

// Validation and header-list budgeting still use the upstream encoder. Only
// already-validated fields are ordered before HPACK sees them. CONNECT keeps
// only :method and :authority; no synthetic :scheme or :path is introduced.
func encodeChromeRequestHeaders(req *http.Request, gzip bool, limit uint64, emit func(string, string)) (httpcommon.EncodeHeadersResult, error) {
	var fields []hpack.HeaderField
	result, err := encodeRequestHeaders(req, gzip, limit, func(name, value string) {
		fields = append(fields, hpack.HeaderField{Name: name, Value: value})
	})
	if err != nil {
		return result, err
	}
	sort.SliceStable(fields, func(i, j int) bool {
		left, right := chromeHeaderRank(fields[i].Name), chromeHeaderRank(fields[j].Name)
		if left != right {
			return left < right
		}
		return fields[i].Name < fields[j].Name
	})
	for _, field := range fields {
		emit(field.Name, field.Value)
	}
	return result, nil
}

func chromeHeaderRank(name string) int {
	switch name {
	case ":method":
		return 0
	case ":authority":
		return 1
	case ":scheme":
		return 2
	case ":path":
		return 3
	case "user-agent":
		return 5
	case "proxy-authorization":
		return 6
	default:
		if strings.HasPrefix(name, ":") {
			return 4
		}
		return 7
	}
}
