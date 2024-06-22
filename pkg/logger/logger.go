/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logger

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"kmesh.net/kmesh/pkg/constants"
)

const (
	logSubsys   = "subsys"
	mapName     = "kmesh_events"
	MAX_MSG_LEN = 255
)

type LogEvent struct {
	len uint32
	Msg string
}

var (
	defaultLogger  = InitializeDefaultLogger(false)
	fileOnlyLogger = InitializeDefaultLogger(true)

	defaultLogLevel = logrus.InfoLevel
	defaultLogFile  = "/var/run/kmesh/daemon.log"

	defaultLogFormat = &logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: false,
	}

	loggerMap = map[string]*logrus.Logger{
		"default":  defaultLogger,
		"fileOnly": fileOnlyLogger,
	}
)

func PrintLogs() error {
	logsPath := defaultLogFile
	file, err := os.Open(logsPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Redirct file contents to STDOUT
	_, err = io.Copy(os.Stdout, file)
	if err != nil {
		return err
	}
	return nil
}

func SetLoggerLevel(loggerName string, level logrus.Level) error {
	logger, exists := loggerMap[loggerName]
	if !exists || logger == nil {
		return fmt.Errorf("logger %s does not exist", loggerName)
	}
	logger.SetLevel(level)
	return nil
}

func GetLoggerLevel(loggerName string) (logrus.Level, error) {
	logger, exists := loggerMap[loggerName]
	if !exists || logger == nil {
		return 0, fmt.Errorf("logger %s does not exist", loggerName)
	}
	return logger.Level, nil
}

/* 
logDumpSpace: 
userspace--> 0100--> 4
tracepipe--> 1000--> 8
 */
func SetBpfLogLevelAndDumpSpace(bpfLogLevel string, dumpSpace string, bpfMap *ebpf.Map) error {
	mapValue := uint32(0)
	l, err := strconv.Atoi(bpfLogLevel)
	if bpfLogLevel != "" && err != nil {
		return err
	}
	if l <= constants.BPF_LOG_DEBUG || l >= constants.BPF_LOG_ERR {
		mapValue = uint32(l)
	}
	dp, err := strconv.Atoi(dumpSpace)
	if dumpSpace != "" && err != nil {
		return err
	}
	if dp == constants.BPF_DUMP_SPACE_USERSPACE || dp == constants.BPF_DUMP_SPACE_TRACE_PIPE {
		mapValue ^= uint32(dp)
	}
	zero := uint32(0)
	return bpfMap.Update(&zero, &mapValue, ebpf.UpdateAny)
}

func GetLoggerNames() []string {
	names := make([]string, 0, len(loggerMap))
	for loggerName := range loggerMap {
		names = append(names, loggerName)
	}
	return names
}

func GetBpfLogLevel(bpfMap *ebpf.Map) (string, string, error) {
	zero := uint32(0)
	var mapValue uint32
	err := bpfMap.Lookup(&zero, &mapValue)
	if err != nil {
		return "", "", err
	}
	l := mapValue & 0b0011
	dp := mapValue >> 2 & 0b0011

	var bpfLogLevel string
	var bpfDumpSpace string
	switch (l) {
	case constants.BPF_LOG_ERR:
		bpfLogLevel = "BPF_LOG_ERR"
	case constants.BPF_LOG_WARN:
		bpfLogLevel = "BPF_LOG_WARN"
	case constants.BPF_LOG_INFO:
		bpfLogLevel = "BPF_LOG_INFO"
	case constants.BPF_LOG_DEBUG:
		bpfLogLevel = "BPF_LOG_DEBUG"
	default:
		bpfLogLevel = "invalid bpf log level"
	}
	switch (dp) {
	case constants.BPF_DUMP_SPACE_USERSPACE:
		bpfDumpSpace = "BPF_DUMP_SPACE_USERSPACE"
	case constants.BPF_DUMP_SPACE_TRACE_PIPE:
		bpfDumpSpace = "BPF_DUMP_SPACE_TRACE_PIPE"
	default:
		bpfDumpSpace = "invalid bpf dump value"
	}

	return bpfLogLevel, bpfDumpSpace, nil
}

// InitializeDefaultLogger return a initialized logger
func InitializeDefaultLogger(onlyFile bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(defaultLogFormat)
	logger.SetLevel(defaultLogLevel)

	path, _ := filepath.Split(defaultLogFile)
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		logger.Fatalf("failed to create log directory: %v", err)
	}

	logfile := &lumberjack.Logger{
		Filename:   defaultLogFile,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28,    //days
		Compress:   false, // disabled by default
	}

	if onlyFile {
		logger.SetOutput(io.Writer(logfile))
	} else {
		logger.SetOutput(io.MultiWriter(os.Stdout, logfile))
	}

	return logger
}

// NewLoggerField allocates a new log entry and adds a field to it.
func NewLoggerField(pkgSubsys string) *logrus.Entry {
	return defaultLogger.WithField(logSubsys, pkgSubsys)
}

// NewLoggerFieldFileOnly don't output log to stdout
func NewLoggerFieldWithoutStdout(pkgSubsys string) *logrus.Entry {
	return fileOnlyLogger.WithField(logSubsys, pkgSubsys)
}

/*
print bpf log to daemon process.
*/
func StartRingBufReader(ctx context.Context, mode string, bpfFsPath string) error {
	var path string

	if mode == constants.AdsMode {
		path = bpfFsPath + "/bpf_kmesh/map"
	} else if mode == constants.WorkloadMode {
		path = bpfFsPath + "/bpf_kmesh_workload/map"
	} else {
		return fmt.Errorf("invalid start mode:%s", mode)
	}
	path = filepath.Join(path, mapName)
	rbMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}

	go handleLogEvents(ctx, rbMap)

	return nil
}

func handleLogEvents(ctx context.Context, rbMap *ebpf.Map) {
	log := NewLoggerField("ebpf")
	events, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Errorf("ringbuf new reader from rb map failed:%v", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := events.Read()
			if err != nil {
				return
			}
			le, err := decodeRecord(record.RawSample)
			if err != nil {
				log.Errorf("ringbuf decode data failed:%v", err)
			}
			log.Infof("%v", le.Msg)
		}
	}
}

// 4 is the msg length, -1 is the '\0' teminate character
func decodeRecord(data []byte) (*LogEvent, error) {
	le := LogEvent{}
	lenOfMsg := binary.NativeEndian.Uint32(data[0:4])
	le.len = uint32(lenOfMsg)
	le.Msg = string(data[4 : 4+lenOfMsg-1])
	return &le, nil
}
