package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type TCPConnectionRaw struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	State         int    `json:"State"`
	OwningProcess int    `json:"OwningProcess"`
}

type TCPConnection struct {
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	State         string `json:"state"`
	StateCode     int    `json:"state_code"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name,omitempty"`
	IsBusiness    bool   `json:"is_business"`
}

type ProcessInfo struct {
	PID         int    `json:"Id"`
	ProcessName string `json:"ProcessName"`
}

type PortStat struct {
	Count        int            `json:"count"`
	Business     int            `json:"business"`
	System       int            `json:"system"`
	Processes    map[string]int `json:"processes,omitempty"`
	States       map[string]int `json:"states,omitempty"`
}

type ConnectionResponse struct {
	BusinessCount      int                   `json:"business_count"`
	SystemCount        int                   `json:"system_count"`
	Total              int                   `json:"total"`
	Timestamp          string                `json:"timestamp"`
	BusinessStates     map[string]int        `json:"business_states,omitempty"`
	SystemStates       map[string]int        `json:"system_states,omitempty"`
	TopProcesses       map[string]int        `json:"top_processes,omitempty"`
	BusinessLocalPorts map[string]*PortStat  `json:"business_local_ports,omitempty"`
	BusinessRemotePorts map[string]*PortStat `json:"business_remote_ports,omitempty"`
	SystemLocalPorts   map[string]*PortStat  `json:"system_local_ports,omitempty"`
	SystemRemotePorts  map[string]*PortStat  `json:"system_remote_ports,omitempty"`
	Connections        []TCPConnection       `json:"connections,omitempty"`
	Error              string                `json:"error,omitempty"`
}

type FilterOptions struct {
	State        string
	OnlyBusiness bool
	LocalPort    int
	RemotePort   int
	ProcessName  string
	ShowDetails  bool
}

var tcpStateNames = map[int]string{
	1:   "CLOSED",
	2:   "LISTENING",
	3:   "SYN_SENT",
	4:   "SYN_RCVD",
	5:   "ESTABLISHED",
	6:   "FIN_WAIT_1",
	7:   "FIN_WAIT_2",
	8:   "CLOSE_WAIT",
	9:   "CLOSING",
	10:  "LAST_ACK",
	11:  "TIME_WAIT",
	12:  "DELETE_TCB",
	100: "BOUND",
}

var systemProcessNames = map[string]bool{
	"system":            true,
	"registry":          true,
	"smss.exe":          true,
	"csrss.exe":         true,
	"wininit.exe":       true,
	"winlogon.exe":      true,
	"services.exe":      true,
	"lsass.exe":         true,
	"svchost.exe":       true,
	"fontdrvhost.exe":   true,
	"dwm.exe":           true,
	"dllhost.exe":       true,
	"taskhostw.exe":     true,
	"runtimebroker.exe": true,
	"searchindexer.exe": true,
	"spoolsv.exe":       true,
	"explorer.exe":      true,
}

func GetTCPStateName(state int) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return strconv.Itoa(state)
}

func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func isSystemProcess(name string) bool {
	return systemProcessNames[strings.ToLower(name)]
}

func isBusinessConnection(conn TCPConnection) bool {
	stateName := conn.State
	if stateName != "ESTABLISHED" && stateName != "CLOSE_WAIT" {
		return false
	}
	if isLoopback(conn.LocalAddress) && isLoopback(conn.RemoteAddress) {
		return false
	}
	if conn.ProcessName != "" && isSystemProcess(conn.ProcessName) {
		return false
	}
	if conn.RemotePort == 0 {
		return false
	}
	return true
}

func GetProcessMap() (map[int]string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-Process | Select-Object -Property Id, ProcessName | ConvertTo-Json`)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return make(map[int]string), nil
	}

	var procs []ProcessInfo
	err = json.Unmarshal([]byte(outputStr), &procs)
	if err != nil {
		var singleProc ProcessInfo
		if err2 := json.Unmarshal([]byte(outputStr), &singleProc); err2 == nil {
			procs = []ProcessInfo{singleProc}
		} else {
			return nil, err
		}
	}

	procMap := make(map[int]string)
	for _, p := range procs {
		procMap[p.PID] = p.ProcessName
	}

	return procMap, nil
}

type TCPConnectionEnriched struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	State         int    `json:"State"`
	OwningProcess int    `json:"OwningProcess"`
	ProcessName   string `json:"ProcessName"`
}

func GetTCPConnections() ([]TCPConnection, error) {
	psScript := `
$procMap = @{}
Get-Process | ForEach-Object { $procMap[[uint32]$_.Id] = $_.ProcessName }
Get-NetTCPConnection | ForEach-Object {
    $owningPid = $_.OwningProcess
    [PSCustomObject]@{
        LocalAddress  = $_.LocalAddress
        LocalPort     = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort    = $_.RemotePort
        State         = [int]$_.State
        OwningProcess = $owningPid
        ProcessName   = $procMap[$owningPid]
    }
} | ConvertTo-Json`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return []TCPConnection{}, nil
	}

	var rawConns []TCPConnectionEnriched
	err = json.Unmarshal([]byte(outputStr), &rawConns)
	if err != nil {
		var singleConn TCPConnectionEnriched
		if err2 := json.Unmarshal([]byte(outputStr), &singleConn); err2 == nil {
			rawConns = []TCPConnectionEnriched{singleConn}
		} else {
			return nil, err
		}
	}

	connections := make([]TCPConnection, 0, len(rawConns))
	for _, raw := range rawConns {
		stateName := GetTCPStateName(raw.State)
		conn := TCPConnection{
			LocalAddress:  raw.LocalAddress,
			LocalPort:     raw.LocalPort,
			RemoteAddress: raw.RemoteAddress,
			RemotePort:    raw.RemotePort,
			State:         stateName,
			StateCode:     raw.State,
			PID:           raw.OwningProcess,
			ProcessName:   raw.ProcessName,
		}
		conn.IsBusiness = isBusinessConnection(conn)
		connections = append(connections, conn)
	}

	return connections, nil
}

func ParseFilterOptions(r *http.Request) FilterOptions {
	opts := FilterOptions{}

	opts.State = strings.ToUpper(r.URL.Query().Get("state"))
	opts.OnlyBusiness = r.URL.Query().Get("only_business") == "true" || r.URL.Query().Get("business") == "true"
	opts.ShowDetails = r.URL.Query().Get("details") == "true"

	if lp := r.URL.Query().Get("local_port"); lp != "" {
		if port, err := strconv.Atoi(lp); err == nil {
			opts.LocalPort = port
		}
	}
	if rp := r.URL.Query().Get("remote_port"); rp != "" {
		if port, err := strconv.Atoi(rp); err == nil {
			opts.RemotePort = port
		}
	}
	opts.ProcessName = strings.ToLower(r.URL.Query().Get("process"))

	return opts
}

func FilterConnections(connections []TCPConnection, opts FilterOptions) []TCPConnection {
	result := make([]TCPConnection, 0)
	for _, conn := range connections {
		if opts.State != "" && conn.State != opts.State {
			continue
		}
		if opts.OnlyBusiness && !conn.IsBusiness {
			continue
		}
		if opts.LocalPort != 0 && conn.LocalPort != opts.LocalPort {
			continue
		}
		if opts.RemotePort != 0 && conn.RemotePort != opts.RemotePort {
			continue
		}
		if opts.ProcessName != "" && !strings.Contains(strings.ToLower(conn.ProcessName), opts.ProcessName) {
			continue
		}
		result = append(result, conn)
	}
	return result
}

func getOrCreatePortStat(m map[string]*PortStat, key string) *PortStat {
	if _, ok := m[key]; !ok {
		m[key] = &PortStat{
			Processes: make(map[string]int),
			States:    make(map[string]int),
		}
	}
	return m[key]
}

func CountConnections(connections []TCPConnection) (int, int, map[string]int, map[string]int, map[string]int, map[string]*PortStat, map[string]*PortStat, map[string]*PortStat, map[string]*PortStat) {
	businessCount := 0
	systemCount := 0
	businessStates := make(map[string]int)
	systemStates := make(map[string]int)
	procCount := make(map[string]int)

	bizLocalPorts := make(map[string]*PortStat)
	bizRemotePorts := make(map[string]*PortStat)
	sysLocalPorts := make(map[string]*PortStat)
	sysRemotePorts := make(map[string]*PortStat)

	for _, conn := range connections {
		procName := conn.ProcessName
		if procName == "" {
			procName = "PID:" + strconv.Itoa(conn.PID)
		}
		procCount[procName]++

		localPortKey := strconv.Itoa(conn.LocalPort)
		remotePortKey := strconv.Itoa(conn.RemotePort)

		if conn.IsBusiness {
			businessCount++
			businessStates[conn.State]++

			blp := getOrCreatePortStat(bizLocalPorts, localPortKey)
			blp.Count++
			blp.Business++
			blp.Processes[procName]++
			blp.States[conn.State]++

			brp := getOrCreatePortStat(bizRemotePorts, remotePortKey)
			brp.Count++
			brp.Business++
			brp.Processes[procName]++
			brp.States[conn.State]++
		} else {
			systemCount++
			systemStates[conn.State]++

			slp := getOrCreatePortStat(sysLocalPorts, localPortKey)
			slp.Count++
			slp.System++
			slp.Processes[procName]++
			slp.States[conn.State]++

			srp := getOrCreatePortStat(sysRemotePorts, remotePortKey)
			srp.Count++
			srp.System++
			srp.Processes[procName]++
			srp.States[conn.State]++
		}
	}

	return businessCount, systemCount, businessStates, systemStates, procCount, bizLocalPorts, bizRemotePorts, sysLocalPorts, sysRemotePorts
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	allConnections, err := GetTCPConnections()
	if err != nil {
		response := ConnectionResponse{
			Error:     err.Error(),
			Timestamp: time.Now().Format(time.RFC3339),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	opts := ParseFilterOptions(r)
	filteredConnections := FilterConnections(allConnections, opts)

	businessCount, systemCount, businessStates, systemStates, procCount, bizLocalPorts, bizRemotePorts, sysLocalPorts, sysRemotePorts := CountConnections(filteredConnections)

	response := ConnectionResponse{
		BusinessCount:       businessCount,
		SystemCount:         systemCount,
		Total:               businessCount + systemCount,
		Timestamp:           time.Now().Format(time.RFC3339),
		BusinessStates:      businessStates,
		SystemStates:        systemStates,
		TopProcesses:        procCount,
		BusinessLocalPorts:  bizLocalPorts,
		BusinessRemotePorts: bizRemotePorts,
		SystemLocalPorts:    sysLocalPorts,
		SystemRemotePorts:   sysRemotePorts,
	}

	if opts.ShowDetails {
		response.Connections = filteredConnections
	}

	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func main() {
	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		if _, err := strconv.Atoi(envPort); err == nil {
			port = envPort
		}
	}

	http.HandleFunc("/api/tcp-connections", connectionHandler)
	http.HandleFunc("/health", healthHandler)

	log.Printf("TCP Connection API server starting on port %s", port)
	log.Printf("Endpoints:")
	log.Printf("  GET /api/tcp-connections - Get TCP connection count")
	log.Printf("      Query params:")
	log.Printf("        only_business=true  - Only show business connections")
	log.Printf("        state=ESTABLISHED   - Filter by state (ESTABLISHED, LISTENING, etc.)")
	log.Printf("        local_port=8080     - Filter by local port")
	log.Printf("        remote_port=443     - Filter by remote port")
	log.Printf("        process=chrome      - Filter by process name")
	log.Printf("        details=true        - Include full connection details in response")
	log.Printf("  GET /health              - Health check")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
