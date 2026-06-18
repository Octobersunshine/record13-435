package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type TCPConnection struct {
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	State         int    `json:"state"`
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

func GetTCPStateName(state int) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return strconv.Itoa(state)
}

type ConnectionResponse struct {
	Total      int             `json:"total"`
	Count      int             `json:"count"`
	Timestamp  string          `json:"timestamp"`
	States     map[string]int  `json:"states,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func GetTCPConnections() ([]TCPConnection, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Json`)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return []TCPConnection{}, nil
	}

	var connections []TCPConnection
	err = json.Unmarshal([]byte(outputStr), &connections)
	if err != nil {
		var singleConn TCPConnection
		if err2 := json.Unmarshal([]byte(outputStr), &singleConn); err2 == nil {
			return []TCPConnection{singleConn}, nil
		}
		return nil, err
	}

	return connections, nil
}

func CountTCPConnections() (int, map[string]int, error) {
	connections, err := GetTCPConnections()
	if err != nil {
		return 0, nil, err
	}

	stateCount := make(map[string]int)
	for _, conn := range connections {
		stateName := GetTCPStateName(conn.State)
		stateCount[stateName]++
	}

	return len(connections), stateCount, nil
}

func connectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	count, states, err := CountTCPConnections()

	response := ConnectionResponse{
		Total:     count,
		Count:     count,
		Timestamp: time.Now().Format(time.RFC3339),
		States:    states,
	}

	if err != nil {
		response.Error = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
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
	log.Printf("  GET /health              - Health check")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
