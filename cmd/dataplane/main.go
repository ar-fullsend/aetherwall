package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type Decision struct {
	Action  string   `json:"action"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
}

func main() {
	listen := flag.String("listen", ":9443", "proxy listen address")
	control := flag.String("control", "http://127.0.0.1:8080", "control plane base URL")
	upstream := flag.String("upstream", "http://127.0.0.1:8787", "default sanctioned upstream")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"plane":"go-dataplane","ok":true}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		identity := r.Header.Get("X-Aetherwall-Identity")
		contract := r.Header.Get("X-Aetherwall-Contract")

		var payload any
		if err := json.Unmarshal(body, &payload); err != nil {
			payload = map[string]any{"text": string(body)}
		}
		reqBody, _ := json.Marshal(map[string]any{
			"payload": payload, "identity": identity, "contract": contract, "destination": *upstream,
		})

		resp, err := http.Post(*control+"/v1/decide", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"action":"deny","reasons":["control plane unreachable: %v"]}`, err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var d Decision
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			http.Error(w, `{"action":"deny","reasons":["undecodable decision"]}`, http.StatusBadGateway)
			return
		}
		w.Header().Set("X-Aetherwall-Action", d.Action)
		if d.Action == "deny" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(d)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"forward": "would-proxy", "upstream": *upstream, "decision": d,
			"enforced": time.Now().UTC().Format(time.RFC3339), "dataplane": "go",
		})
	})

	log.Printf("aetherwall go dataplane on %s control=%s", *listen, *control)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
