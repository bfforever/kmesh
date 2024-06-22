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

package status

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"regexp"
	"strconv"
	"time"

	// nolint
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("status")

const (
	adminAddr = "localhost:15200"

	patternHelp               = "/help"
	patternOptions            = "/options"
	patternBpfAdsMaps         = "/debug/bpf/ads"
	configDumpPrefix          = "/debug/config_dump"
	patternConfigDumpAds      = configDumpPrefix + "/ads"
	patternConfigDumpWorkload = configDumpPrefix + "/workload"
	patternReadyProbe         = "/debug/ready"
	patternLoggers            = "/debug/loggers"
	patternBpfLogLevel        = "/debug/bpfLogLevel/"

	httpTimeout = time.Second * 20
)

type Server struct {
	config         *options.BootstrapConfigs
	xdsClient      *controller.XdsClient
	mux            *http.ServeMux
	server         *http.Server
	bpfWorkloadObj *bpf.BpfKmeshWorkload
}

func GetConfigDumpAddr(mode string) string {
	return "http://" + adminAddr + configDumpPrefix + "/" + mode
}

func NewServer(c *controller.XdsClient, configs *options.BootstrapConfigs, bpfWorkloadObj *bpf.BpfKmeshWorkload) *Server {
	s := &Server{
		config:         configs,
		xdsClient:      c,
		mux:            http.NewServeMux(),
		bpfWorkloadObj: bpfWorkloadObj,
	}
	s.server = &http.Server{
		Addr:         adminAddr,
		Handler:      s.mux,
		ReadTimeout:  httpTimeout,
		WriteTimeout: httpTimeout,
	}

	s.mux.HandleFunc(patternHelp, s.httpHelp)
	s.mux.HandleFunc(patternOptions, s.httpOptions)
	s.mux.HandleFunc(patternBpfAdsMaps, s.bpfAdsMaps)
	s.mux.HandleFunc(patternConfigDumpAds, s.configDumpAds)
	s.mux.HandleFunc(patternConfigDumpWorkload, s.configDumpWorkload)
	s.mux.HandleFunc(patternLoggers, s.loggersHandler)
	s.mux.HandleFunc(patternBpfLogLevel, s.bpfLogLevel)

	// TODO: add dump certificate, authorizationPolicies and services
	s.mux.HandleFunc(patternReadyProbe, s.readyProbe)

	// support pprof
	s.mux.HandleFunc("/debug/pprof/", pprof.Index)
	s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return s
}

func (s *Server) httpHelp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "\t%s: %s\n", patternHelp,
		"print list of commands")
	fmt.Fprintf(w, "\t%s: %s\n", patternOptions,
		"print config options")
	fmt.Fprintf(w, "\t%s: %s\n", patternBpfAdsMaps,
		"print bpf kmesh maps in kernel")
	fmt.Fprintf(w, "\t%s: %s\n", patternConfigDumpAds,
		"dump xDS[Listener, Route, Cluster] configurations")
	fmt.Fprintf(w, "\t%s: %s\n", patternConfigDumpWorkload,
		"dump workload configurations")
	fmt.Fprintf(w, "\t%s: %s\n", patternLoggers,
		"get or set logger level")
}

func (s *Server) httpOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, s.config.String())
}

func (s *Server) bpfAdsMaps(w http.ResponseWriter, r *http.Request) {
	client := s.xdsClient
	if client == nil || client.AdsController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

	w.WriteHeader(http.StatusOK)
	cache := client.AdsController.Processor.Cache
	dynamicRes := &adminv2.ConfigResources{}

	dynamicRes.ClusterConfigs = cache.ClusterCache.DumpBpf()
	dynamicRes.ListenerConfigs = cache.ListenerCache.DumpBpf()
	dynamicRes.RouteConfigs = cache.RouteCache.DumpBpf()
	ads.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&adminv2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

type LoggerInfo struct {
	Name  string `json:"name,omitempty"`
	Level string `json:"level,omitempty"`
	BpfLogLevel string `json:"bpfloglevel,omitempty"`
	BpfLogDumpSpace string `json:"bpflogdumpspace,omitempty"`
}

func (s *Server) loggersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.getLoggerLevel(w, r)
	} else if r.Method == http.MethodPost {
		s.setLoggerLevel(w, r)
	} else {
		// otherwise, return 404 not found
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) getLoggerLevel(w http.ResponseWriter, r *http.Request) {
	loggerName := r.URL.Query().Get("name")
	loggerLevel, err := logger.GetLoggerLevel(loggerName)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", err.Error())
		return
	}
	bpfloglevel, dumpSpace, err := logger.GetBpfLogLevel(s.bpfWorkloadObj.SockConn.BpfLogLevel)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", err.Error())
		return
	}
	loggerInfo := LoggerInfo{
		Name:  loggerName,
		Level: loggerLevel.String(),
		BpfLogLevel: bpfloglevel,
		BpfLogDumpSpace: dumpSpace,
	}
	data, err := json.MarshalIndent(&loggerInfo, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal logger info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) setLoggerLevel(w http.ResponseWriter, r *http.Request) {
	var (
		loggerInfo  LoggerInfo
		loggerLevel logrus.Level
	)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %s\n", "Error reading request body", err.Error())
		return
	}

	if err = json.Unmarshal(body, &loggerInfo); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %s\n", "Invalid request body format", err.Error())
		return
	}

	if loggerLevel, err = logrus.ParseLevel(loggerInfo.Level); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %s\n", "Invalid request body format", err.Error())
		return
	}

	if err = logger.SetLoggerLevel(loggerInfo.Name, loggerLevel); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", err.Error())
		return
	}

	if err = logger.SetBpfLogLevelAndDumpSpace(loggerInfo.BpfLogLevel, loggerInfo.BpfLogDumpSpace, s.bpfWorkloadObj.SockConn.BpfLogLevel); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", err.Error())
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) configDumpAds(w http.ResponseWriter, r *http.Request) {
	client := s.xdsClient 
	if client == nil || client.AdsController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

	w.WriteHeader(http.StatusOK)
	cache := client.AdsController.Processor.Cache
	dynamicRes := &adminv2.ConfigResources{}

	dynamicRes.ClusterConfigs = cache.ClusterCache.Dump()
	dynamicRes.ListenerConfigs = cache.ListenerCache.Dump()
	dynamicRes.RouteConfigs = cache.RouteCache.Dump()
	ads.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&adminv2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

type WorkloadDump struct {
	Workloads []*Workload
	Services  []*Service
	// TODO: add authorization
	Policies []*security.Authorization
}

func (s *Server) configDumpWorkload(w http.ResponseWriter, r *http.Request) {
	client := s.xdsClient
	if client == nil || client.WorkloadController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

	workloads := client.WorkloadController.Processor.WorkloadCache.List()
	services := client.WorkloadController.Processor.ServiceCache.List()
	workloadDump := WorkloadDump{
		Workloads: make([]*Workload, 0, len(workloads)),
		Services:  make([]*Service, 0, len(services)),
	}
	for _, w := range workloads {
		workloadDump.Workloads = append(workloadDump.Workloads, ConvertWorkload(w))
	}
	for _, s := range services {
		workloadDump.Services = append(workloadDump.Services, ConvertService(s))
	}
	printWorkloadDump(w, workloadDump)
}

func (s *Server) readyProbe(w http.ResponseWriter, r *http.Request) {
	// TODO: Add some components check
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) bpfLogLevel(w http.ResponseWriter, r *http.Request) {
	pattern := regexp.MustCompile(`^/debug/bpfLogLevel/(\d+)$`)
	matches := pattern.FindStringSubmatch(r.URL.Path)
	if len(matches) > 1 {
		level, err := strconv.Atoi(matches[1])
		if err != nil || (level < constants.BPF_LOG_ERR || level > constants.BPF_LOG_DEBUG) {
			http.Error(w, "Invalid log level", http.StatusBadRequest)
			return
		}
		key := uint32(0)
		levelPtr := uint32(level)
		if err := s.bpfWorkloadObj.SockConn.BpfLogLevel.Update(&key, &levelPtr, ebpf.UpdateAny); err != nil {
			http.Error(w, fmt.Errorf("update log level error:%v", err).Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "BPF Log Level: %d\n", level)
	} else {
		http.NotFound(w, r)
	}
}

func (s *Server) StartServer() {
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			log.Errorf("Failed to start status server: %v", err)
		}
	}()
}

func (s *Server) StopServer() error {
	return s.server.Close()
}

func printWorkloadDump(w http.ResponseWriter, wd WorkloadDump) {
	data, err := json.MarshalIndent(wd, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal WorkloadDump: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
