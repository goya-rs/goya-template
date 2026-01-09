package logs

import (
	"path/filepath"
	"strings"
)

type LogLevel uint8

const (
	LogError LogLevel = 1
	LogWarn  LogLevel = 2
	LogInfo  LogLevel = 3
	LogDebug LogLevel = 4
	LogTrace LogLevel = 5
)

type Header struct {
	Target  string
	Level   LogLevel
	Module  string
	File    string
	Line    uint32
	NumArgs uint32
}

func (l LogLevel) String() string {
	switch l {
	case LogError:
		return "ERROR"
	case LogWarn:
		return "WARN"
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	case LogTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

func filenameWithoutExt(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
