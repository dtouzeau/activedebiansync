package utils

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func StrToInt(svalue string) int {
	svalue = strings.TrimSpace(svalue)

	if svalue == "true" {
		return 1
	}
	if svalue == "false" {
		return 0
	}
	if svalue == "1" {
		return 1
	}
	if svalue == "0" {
		return 0
	}

	svalue = strings.Replace(svalue, ",", ".", 1)

	if strings.Contains(svalue, ".") {
		parts := strings.Split(svalue, ".")
		svalue = parts[0]
	}

	if len(svalue) == 0 {
		return 0
	}
	tkint, err := strconv.Atoi(string(svalue))
	if err == nil {
		return tkint
	}
	return 0
}
func StrToInt64(svalue string) int64 {
	svalue = strings.TrimSpace(svalue)
	n, err := strconv.ParseInt(svalue, 10, 64)
	if err == nil {
		return n
	}
	return 0
}
func TimeStampToString() string {
	return Int64ToString(TimeStamp())
}
func Int64ToString(svalue int64) string {
	return strconv.FormatInt(svalue, 10)
}
func TimeStamp() int64 {
	location, _ := time.LoadLocation("Local")
	currentTime := time.Now().In(location)
	return currentTime.Unix()
}
func FilePutContentsBytes(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}
func CreateDir(directoryPath string) error {
	directoryPath = strings.TrimSpace(directoryPath)
	if directoryPath == "" {
		return errors.New("You must provide a directory path")
	}
	tb := strings.Split(directoryPath, "/")
	if len(tb) < 2 || !strings.Contains(directoryPath, "/") {
		zfunc := ""
		for skip := 0; ; skip++ {
			pc, file, line, ok := runtime.Caller(skip)
			if !ok {
				break
			}
			funcName := runtime.FuncForPC(pc).Name()
			funcName = strings.ReplaceAll(funcName, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			file = strings.ReplaceAll(file, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
			funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")
			zfunc = zfunc + "," + funcName + " Line " + Int64ToString(int64(line))

		}
		return fmt.Errorf("%v Create Directory suspicious [%v] in %v", GetCalleRuntime(), directoryPath, zfunc)
	}
	directoryPath = strings.TrimSpace(directoryPath)
	directoryPath = strings.ReplaceAll(directoryPath, `'`, "")
	directoryPath = strings.ReplaceAll(directoryPath, `"`, "")
	directoryPath = strings.TrimSpace(directoryPath)
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0o755)
		if err != nil {
			return err
		}

	}
	return nil
}

// RegexGroup1 extracts the first capture group from a regex match
func RegexGroup1(re *regexp.Regexp, content string) string {
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
