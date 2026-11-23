// Package main: infmail-obs — observability микросервис на Go (П.3.6).
//
// Читает локальные файлы валидатора (rewards.json, payout_ledger.json, kv.json, chunks/manifest count)
// и отдаёт сводку через HTTP. Без внешних зависимостей (только stdlib).
//
// Запуск:
//   INFMAIL_OBS_PORT=9100 INFMAIL_OBS_DATA_DIR=/opt/infnode ./infmail-obs
//
// Роуты:
//   GET /healthz  — liveness
//   GET /stats    — общая сводка (rewards, payouts, kv-размер, chunk-размер)
//   GET /nodes    — список нод с весами (из rewards.json)
//   GET /payouts  — последние записи payout_ledger.json
//   GET /metrics  — Prometheus-совместимый метрики (числовые)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Port    string
	DataDir string
	APIBase string
	LogPath string
}

func loadConfig() Config {
	port := os.Getenv("INFMAIL_OBS_PORT")
	if port == "" {
		port = "9100"
	}
	dataDir := os.Getenv("INFMAIL_OBS_DATA_DIR")
	if dataDir == "" {
		dataDir = "/opt/infnode"
	}
	apiBase := os.Getenv("INFMAIL_API_URL")
	if apiBase == "" {
		apiBase = "http://127.0.0.1:3001"
	}
	logPath := os.Getenv("INFMAIL_WATCHER_LOG")
	if logPath == "" {
		logPath = "/opt/infnode/alerts.log"
	}
	return Config{Port: port, DataDir: dataDir, APIBase: apiBase, LogPath: logPath}
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// rewards.json: { ts, interval_secs, nodes: [{ name, node_id, weight, total_bytes, uptime_ratio, trust_score }] }
type rewardsNode struct {
	Name        string  `json:"name"`
	NodeID      string  `json:"node_id"`
	Weight      float64 `json:"weight"`
	TotalBytes  uint64  `json:"total_bytes"`
	UptimeRatio float64 `json:"uptime_ratio"`
	TrustScore  uint64  `json:"trust_score"`
	ProofOK     uint64  `json:"proof_ok"`
	ProofTotal  uint64  `json:"proof_chunks"`
}

type rewardsFile struct {
	TS           int64         `json:"ts"`
	IntervalSecs int64         `json:"interval_secs"`
	Nodes        []rewardsNode `json:"nodes"`
}

// payout_ledger.json: массив [{ ts, pool_ton, total_weight, payouts: [...] }]
type payoutEntry struct {
	NodeID  string  `json:"node_id"`
	Name    string  `json:"name"`
	Weight  float64 `json:"weight"`
	ShareNT int64   `json:"share_nt"`
	ShareTON float64 `json:"share_ton"`
	Status  string  `json:"status"`
}

type ledgerEntry struct {
	TS          int64         `json:"ts"`
	PoolTON     float64       `json:"pool_ton"`
	TotalWeight float64       `json:"total_weight"`
	Payouts     []payoutEntry `json:"payouts"`
}

type statsCache struct {
	mu          sync.Mutex
	lastFetch   time.Time
	rewards     *rewardsFile
	rewardsErr  error
	ledger      []ledgerEntry
	ledgerErr   error
	kvBytes     int64
	kvKeys      int
	chunksMail  int
	chunksFiles int
}

func (c *statsCache) refresh(dataDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastFetch) < 5*time.Second {
		return
	}
	c.lastFetch = time.Now()

	// rewards.json
	rp := filepath.Join(dataDir, "rewards.json")
	if b, err := readFile(rp); err == nil {
		var rf rewardsFile
		if err := json.Unmarshal(b, &rf); err == nil {
			c.rewards = &rf
			c.rewardsErr = nil
		} else {
			c.rewardsErr = err
		}
	} else {
		c.rewardsErr = err
	}

	// payout_ledger.json
	lp := filepath.Join(dataDir, "payout_ledger.json")
	if b, err := readFile(lp); err == nil {
		var arr []ledgerEntry
		if err := json.Unmarshal(b, &arr); err == nil {
			c.ledger = arr
			c.ledgerErr = nil
		} else {
			c.ledgerErr = err
		}
	} else {
		c.ledgerErr = err
		c.ledger = nil
	}

	// kv.json: ключи + размер
	kp := filepath.Join(dataDir, "kv.json")
	if info, err := os.Stat(kp); err == nil {
		c.kvBytes = info.Size()
	}
	c.kvKeys = 0
	if b, err := readFile(kp); err == nil {
		// быстрый подсчёт top-level ключей через map[string]json.RawMessage
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err == nil {
			c.kvKeys = len(m)
		}
	}

	// chunks/
	c.chunksMail = countChunks(filepath.Join(dataDir, "chunks", "mail"))
	c.chunksFiles = countChunks(filepath.Join(dataDir, "chunks", "files"))
}

func countChunks(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"status": "ok",
		"ts":     time.Now().Unix(),
		"svc":    "infmail-obs",
	})
}

func (c *statsCache) handleStats(w http.ResponseWriter, r *http.Request, dataDir string) {
	c.refresh(dataDir)
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]any{
		"data_dir":  dataDir,
		"ts":        time.Now().Unix(),
		"kv_bytes":  c.kvBytes,
		"kv_keys":   c.kvKeys,
		"chunks":    map[string]int{"mail": c.chunksMail, "files": c.chunksFiles},
		"rewards":   c.rewards,
		"ledger":    map[string]any{"entries": len(c.ledger), "error": errStr(c.ledgerErr)},
	}
	writeJSON(w, 200, out)
}

func (c *statsCache) handleNodes(w http.ResponseWriter, r *http.Request, dataDir string) {
	c.refresh(dataDir)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rewards == nil {
		writeJSON(w, 500, map[string]string{"err": errStr(c.rewardsErr)})
		return
	}
	writeJSON(w, 200, map[string]any{
		"ts":    c.rewards.TS,
		"nodes": c.rewards.Nodes,
	})
}

func (c *statsCache) handlePayouts(w http.ResponseWriter, r *http.Request, dataDir string) {
	c.refresh(dataDir)
	c.mu.Lock()
	defer c.mu.Unlock()
	// возвращаем последние 10 записей (новые сверху)
	n := len(c.ledger)
	limit := 10
	if n > limit {
		n = limit
	}
	out := make([]ledgerEntry, 0, n)
	for i := len(c.ledger) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, c.ledger[i])
	}
	writeJSON(w, 200, out)
}

func (c *statsCache) handleMetrics(w http.ResponseWriter, r *http.Request, dataDir string) {
	c.refresh(dataDir)
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "# HELP infmail_kv_keys Number of keys in kv.json\n")
	fmt.Fprintf(&b, "# TYPE infmail_kv_keys gauge\n")
	fmt.Fprintf(&b, "infmail_kv_keys %d\n", c.kvKeys)
	fmt.Fprintf(&b, "# HELP infmail_kv_bytes Size of kv.json in bytes\n")
	fmt.Fprintf(&b, "# TYPE infmail_kv_bytes gauge\n")
	fmt.Fprintf(&b, "infmail_kv_bytes %d\n", c.kvBytes)
	fmt.Fprintf(&b, "# HELP infmail_chunks_total Number of chunks by bucket\n")
	fmt.Fprintf(&b, "# TYPE infmail_chunks_total gauge\n")
	fmt.Fprintf(&b, "infmail_chunks_total{bucket=\"mail\"} %d\n", c.chunksMail)
	fmt.Fprintf(&b, "infmail_chunks_total{bucket=\"files\"} %d\n", c.chunksFiles)
	if c.rewards != nil {
		fmt.Fprintf(&b, "# HELP infmail_node_weight Node weight from rewards.json\n")
		fmt.Fprintf(&b, "# TYPE infmail_node_weight gauge\n")
		for _, n := range c.rewards.Nodes {
			fmt.Fprintf(&b, "infmail_node_weight{name=\"%s\"} %g\n", n.Name, n.Weight)
		}
	}
	if len(c.ledger) > 0 {
		last := c.ledger[len(c.ledger)-1]
		fmt.Fprintf(&b, "# HELP infmail_payout_pool_ton Last payout pool TON\n")
		fmt.Fprintf(&b, "# TYPE infmail_payout_pool_ton gauge\n")
		fmt.Fprintf(&b, "infmail_payout_pool_ton %g\n", last.PoolTON)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// ---------- Watcher (anomaly detection, на том же порту) ----------

type Alert struct {
	TS       time.Time `json:"ts"`
	Severity string    `json:"severity"` // info, warn, critical
	Source   string    `json:"source"`
	Message  string    `json:"message"`
}

type Watcher struct {
	cfg     Config
	mu      sync.Mutex
	alerts  []Alert
	lastRun time.Time
	checks  map[string]bool // name -> ok
}

func NewWatcher(cfg Config) *Watcher {
	return &Watcher{cfg: cfg, alerts: []Alert{}, checks: map[string]bool{}}
}

func (w *Watcher) logAlert(a Alert) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alerts = append(w.alerts, a)
	if len(w.alerts) > 200 {
		w.alerts = w.alerts[len(w.alerts)-200:]
	}
	// write to file
	if f, err := os.OpenFile(w.cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		enc := json.NewEncoder(f)
		_ = enc.Encode(a)
		f.Close()
	}
	sev := strings.ToUpper(a.Severity)
	log.Printf("[%s] %s: %s", sev, a.Source, a.Message)
}

func (w *Watcher) checkAPI() {
	url := w.cfg.APIBase + "/api/v1/pricing"
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "critical", Source: "api", Message: fmt.Sprintf("API недоступен: %v", err)})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		w.logAlert(Alert{TS: time.Now(), Severity: "critical", Source: "api", Message: fmt.Sprintf("API status %d", resp.StatusCode)})
		return
	}
	w.mu.Lock()
	w.checks["api"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkKV() {
	path := filepath.Join(w.cfg.DataDir, "kv.json")
	info, err := os.Stat(path)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "kv", Message: fmt.Sprintf("kv.json не найден: %v", err)})
		return
	}
	if info.Size() > 100*1024*1024 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "kv", Message: fmt.Sprintf("kv.json вырос до %d MB", info.Size()/1024/1024)})
	}
	w.mu.Lock()
	w.checks["kv"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkRewards() {
	path := filepath.Join(w.cfg.DataDir, "rewards.json")
	b, err := os.ReadFile(path)
	if err != nil {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "rewards", Message: fmt.Sprintf("rewards.json не найден: %v", err)})
		return
	}
	var rf struct {
		TS int64 `json:"ts"`
	}
	_ = json.Unmarshal(b, &rf)
	if rf.TS > 0 {
		ageMin := (time.Now().UnixMilli() - rf.TS) / 60000
		if ageMin > 30 {
			w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "rewards", Message: fmt.Sprintf("rewards.json не обновлялся %d мин", ageMin)})
		}
	}
	w.mu.Lock()
	w.checks["rewards"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkPayouts() {
	path := filepath.Join(w.cfg.DataDir, "payout_ledger.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return // необязательный файл
	}
	var ledger []struct {
		Payouts []struct {
			Status string `json:"status"`
		} `json:"payouts"`
	}
	_ = json.Unmarshal(b, &ledger)
	oldPending := 0
	for _, e := range ledger {
		for _, p := range e.Payouts {
			if p.Status == "pending" {
				oldPending++
			}
		}
	}
	if oldPending > 50 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "payouts", Message: fmt.Sprintf("%d pending payouts — оператор не раздаёт", oldPending)})
	}
	w.mu.Lock()
	w.checks["payouts"] = true
	w.mu.Unlock()
}

func (w *Watcher) checkChunks() {
	chunksDir := filepath.Join(w.cfg.DataDir, "chunks", "mail")
	filesDir := filepath.Join(w.cfg.DataDir, "chunks", "files")
	chunkCount := 0
	if entries, err := os.ReadDir(chunksDir); err == nil {
		chunkCount += len(entries)
	}
	if entries, err := os.ReadDir(filesDir); err == nil {
		chunkCount += len(entries)
	}
	if chunkCount > 100000 {
		w.logAlert(Alert{TS: time.Now(), Severity: "warn", Source: "chunks", Message: fmt.Sprintf("чанков > 100k: %d", chunkCount)})
	}
	w.mu.Lock()
	w.checks["chunks"] = true
	w.mu.Unlock()
}

func (w *Watcher) runOnce() {
	w.checkAPI()
	w.checkKV()
	w.checkRewards()
	w.checkPayouts()
	w.checkChunks()
	w.mu.Lock()
	w.lastRun = time.Now()
	w.mu.Unlock()
}

func (w *Watcher) handleAlerts(w2 http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w2.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w2).Encode(map[string]any{"alerts": w.alerts})
}

func main() {
	cfg := loadConfig()
	cache := &statsCache{}
	watcher := NewWatcher(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) { cache.handleStats(w, r, cfg.DataDir) })
	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) { cache.handleNodes(w, r, cfg.DataDir) })
	mux.HandleFunc("/payouts", func(w http.ResponseWriter, r *http.Request) { cache.handlePayouts(w, r, cfg.DataDir) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { cache.handleMetrics(w, r, cfg.DataDir) })
	mux.HandleFunc("/alerts", watcher.handleAlerts)

	// фоновый цикл проверок (каждые 60с)
	go func() {
		time.Sleep(2 * time.Second)
		watcher.runOnce()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			watcher.runOnce()
		}
	}()

	// поддержка полного адреса: "9100" → ":9100", "127.0.0.1:9100" → как есть
	addr := cfg.Port
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	log.Printf("infmail-obs (ops, объединённый) listening on %s, data_dir=%s", addr, cfg.DataDir)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

	_ = sort.Strings
}