package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Finding struct {
	Source    string                 `json:"source"`
	IP        string                 `json:"ip,omitempty"`
	Hostname  string                 `json:"hostname,omitempty"`
	Summary   string                 `json:"summary"`
	Severity  string                 `json:"severity"`
	Priority  string                 `json:"priority,omitempty"`
	Timestamp string                 `json:"timestamp,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

const FINDINGS_FILE = "data/findings_persist.json"

var (
	findings = make([]Finding, 0)
	seenKeys = make(map[string]bool)
	mutex    sync.Mutex
)

func loadFindings() {
	data, err := os.ReadFile(FINDINGS_FILE)
	if err != nil {
		return
	}
	var loaded []Finding
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	for _, f := range loaded {
		key := f.Source + ":" + f.Summary
		seenKeys[key] = true
		findings = append(findings, f)
	}
	log.Printf("[*] Loaded %d findings from disk", len(findings))
}

func saveFindings() {
	os.MkdirAll("data", 0755)
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(FINDINGS_FILE, data, 0644)
}

func dedupeKey(f Finding) string {
	return f.Source + ":" + f.Summary
}

func observerFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var f Finding
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key := dedupeKey(f)
	mutex.Lock()
	if seenKeys[key] {
		mutex.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "DUP")
		return
	}
	seenKeys[key] = true
	if f.Timestamp == "" {
		f.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	findings = append(findings, f)
	go saveFindings()
	mutex.Unlock()

	summary := f.Summary
	if len(summary) > 100 {
		summary = summary[:100]
	}
	log.Printf("[+] New finding from %s: %s", f.Source, summary)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

func getFindings(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(findings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	loadFindings()
	http.HandleFunc("/observer_feed", observerFeed)
	http.HandleFunc("/findings", getFindings)
	fmt.Println("BugBounty Observer Server started on http://localhost:8080")
	fmt.Println("   POST /observer_feed - добавить находку")
	fmt.Println("   GET  /findings     - получить все находки")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
