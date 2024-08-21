// Package main is a simple workload to analyze health data securely.
//
// Sets up a websocket server to receive health data from UWEAR.
// Requests a custom token from the Attestation service.
// Uses the token retrieve the health data from UWEAR
// Runs a sleep algorithm on the PHI.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"google3/third_party/golang/go_net/http2/http2"

	"google3/third_party/golang/gorilla/websocket/websocket"
)

var (
	socketPath    = "/run/container_launcher/teeserver.sock"
	tokenEndpoint = "http://localhost/v1/token"
	contentType   = "application/json"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Handler creates a multiplexer for the server.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/connection", handleConnectionRequest)
	return mux
}

func getInboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func getCustomToken(nonce string) ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	body := fmt.Sprintf(`{
		"audience": "uwear",
		"nonces": ["%s"],
		"token_type": "PKI"
	}`, nonce)

	resp, err := httpClient.Post(tokenEndpoint, contentType, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	fmt.Printf("Response from launcher: %v\n", resp)
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read resp.Body: %w", err)
	}
	fmt.Printf("Token from the attestation service: %s\n", text)

	return text, nil
}

func getEKMHashFromRequest(r *http.Request) (string, error) {
	ekm, err := r.TLS.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		err := fmt.Errorf("failed to get EKM from inbound http request: %w", err)
		return "", err
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	fmt.Printf("EKM: %v\nSHA hash: %v", ekm, hash)
	return hash, nil
}

type healthData struct {
	Name  string
	Age   int
	Sleep sleepData
}

type sleepData struct {
	Light sleepTime
	Deep  sleepTime
	Rem   sleepTime
}

type sleepTime struct {
	Minutes float64
}

func handleConnectionRequest(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP Connection to a websocket.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("failed to upgrade connection to a websocket with err: %v\n", err)
		return
	}
	defer conn.Close()

	// Get EKM
	hash, err := getEKMHashFromRequest(r)
	if err != nil {
		fmt.Printf("Failed to get EKM: %v", err)
	}

	// Request token with TLS Exported Keying Material (EKM) hashed.
	token, err := getCustomToken(hash)
	if err != nil {
		fmt.Printf("failed to get custom token from token endpoint: %v", err)
		return
	}

	// Respond to the client with the token.
	conn.WriteMessage(websocket.TextMessage, token)

	// Read the sensitive data
	_, content, err := conn.ReadMessage()
	if err != nil {
		fmt.Printf("failed to read message from the connection: %v\n", err)
	}
	fmt.Printf("Received content from other side, %v\n", string(content))

	var healthData healthData
	err = json.Unmarshal(content, &healthData)
	if err != nil {
		fmt.Printf("Failed to unmarshal health data: %v\n", err)
	}

	// Run algorithms on health data.
	result := calculateSleepQuality(healthData)
	fmt.Printf("Sleep quality result: %v\n", result)

	// Terminate the connection in case the client failed to connect.
	fmt.Println("terminating connection")
	err = conn.Close()
	if err != nil {
		fmt.Printf("Failed to close the conn. Not failing. err: %v\n", err)
	}
}

func calculateSleepQuality(healthData healthData) string {
	fmt.Printf("Sleep data: %v\n", healthData)

	totalSleepMins := healthData.Sleep.Light.Minutes + healthData.Sleep.Deep.Minutes + healthData.Sleep.Rem.Minutes

	if totalSleepMins > 480 {
		return "total sleep time is less than 8 hours"
	}

	if healthData.Sleep.Rem.Minutes/totalSleepMins < .20 {
		return "rem sleep time is less than 25% of total sleep time"
	}

	if healthData.Sleep.Light.Minutes/totalSleepMins < .50 {
		return "light sleep time is less than 50% of total sleep time"
	}

	if healthData.Sleep.Deep.Minutes/totalSleepMins < .20 {
		return "deep sleep time is less than 25% of total sleep time"
	}

	return "great sleep!"
}

func main() {
	var err error
	tlsConfig := &tls.Config{}

	local := getInboundIP()
	fmt.Printf("#####----- Local IP Address is %v -----#####\n", local)

	server := &http.Server{
		Addr:      ":8081",
		Handler:   Handler(),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("./server.crt", "./server.key")
	fmt.Printf("Unable to start Server %v", err)
}
